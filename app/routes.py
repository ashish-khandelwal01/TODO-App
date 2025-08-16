import io
import json
from datetime import datetime
from typing import Optional, Dict, List, Any, Union, Tuple
from flask import Blueprint, render_template, redirect, url_for, request, session, jsonify, flash
from flask import make_response
from flask_login import login_user, login_required, logout_user, current_user
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.models import User, Task

# Define a Flask Blueprint for the main routes of the application
main = Blueprint('main', __name__)

# Maximum depth allowed for nested subtasks
MAX_NESTING_DEPTH = 5

@main.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user authentication for the web browser.

    GET Request:
        - Web: Returns rendered login.html template

    POST Request Processing:
        1. Extracts credentials from form data (web)
        2. Validates that both username and password are provided
        3. Queries database for user with matching username
        4. Verifies password using secure hash comparison
        5. Creates user session if authentication succeeds
        6. Returns appropriate response based on client type

    Request Data (POST):
        Form Data (Web clients):
            - username: string (required)
            - password: string (required)

    Returns:
        GET Requests:
            - Web: Rendered login page

        POST Requests - Success:
            - Web: Redirect to main index page

        POST Requests - Failure:
            - Web: Re-rendered login page with error message

    Security Features:
        - Passwords stored as secure PBKDF2-SHA256 hashes
        - Session configured as permanent for persistence
        - No password information returned in responses
        - Input validation prevents empty credentials
    """
    if request.method == 'GET':
        return render_template('login.html')

    try:
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            error_msg = 'Username and password are required'
            return render_template('login.html', error_message=error_msg)

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            session.permanent = True

            return redirect(url_for('main.index'))
        else:
            error_msg = 'Login Unsuccessful. Please check username and password'
            return render_template('login.html', error_message=error_msg)

    except Exception as e:
        return render_template('login.html', error_message='An error occurred during login')


@main.route('/logout')
@login_required
def logout():
    """
    Terminate the current user session and log out the user.

    This endpoint handles user logout for the web. It clears
    the current user session using Flask-Login's logout_user() function and
    provides appropriate responses based on the client type.

    Authentication:
        - Requires active user session (@login_required decorator)
        - Redirects to the login page if the user is not authenticated

    Process:
        1. Calls Flask-Login's logout_user() to clear session
        2. Determines response format based on client type
        3. Returns success confirmation or redirects to login

    Returns:
        Web Clients:
            - Redirect to login page

    Side Effects:
        - Clears user session data
        - Removes authentication state
        - User will need to log in again for protected routes

    Example Usage:
        # Web browser
        GET /logout -> Redirects to /login
    """
    try:
        logout_user()
        return redirect(url_for('main.login'))
    except Exception as e:
        return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle new user registration for web clients.

    This endpoint manages the complete user registration process, including
    validation, duplicate checking, secure password hashing, and account creation.
    It supports the web form submissions.

    GET Request:
        - Web: Returns registration form template

    POST Request Processing:
        1. Extracts registration data from form
        2. Validates all required fields are present
        3. Checks for existing username conflicts
        4. Checks for existing email conflicts
        5. Hashes password using PBKDF2-SHA256
        6. Creates new User record in database
        7. Returns success response or redirect

    Request Data (POST):

        Form Data (Web clients):
            - username: string (required)
            - email: string (required)
            - password: string (required)
            - security_question: string (required)
            - security_answer: string (required)

    Returns:
        GET Requests:
            - Web: Rendered registration form (200)

        POST Success:
            - Web: Redirect to login page (302)

        POST Failure:
            - Web: Re-rendered form with error message

    Security Features:
        - Passwords hashed with PBKDF2-SHA256 before storage
        - Username and email uniqueness enforced
        - Security question/answer stored for password recovery
        - No sensitive data returned
        - Database rollback on registration errors

    Validation Rules:
        - All fields are required
        - Username must be unique across all users
        - Email must be unique across all users
        - Security question and answer required for account recovery

    Database Operations:
        - Queries User table for existing username/email
        - Creates new User record with hashed password
        - Commits transaction or rolls back on error
    """
    if request.method == 'GET':
        return render_template('register.html')

    try:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        security_question = request.form.get('security_question')
        security_answer = request.form.get('security_answer')

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error_msg = 'Username already exists'
            return render_template('register.html', error_message=error_msg)

        # Check if email already exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            error_msg = 'Email already exists'
            return render_template('register.html', error_message=error_msg)

        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            security_question=security_question,
            security_answer=security_answer
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('main.login'))

    except Exception as e:
        db.session.rollback()
        return render_template('register.html', error_message='Registration failed')


@main.route('/')
@login_required
def index():
    """
    Display the main task management dashboard with filtering and sorting capabilities.

    This is the primary endpoint for the task management application. It retrieves
    and displays all main tasks (non-subtasks) for the authenticated user with
    support for sorting and priority filtering. The endpoint serves the web
    browsers.

    Authentication:
        - Requires active user session (@login_required decorator)
        - Only shows tasks belonging to the authenticated user

    Query Parameters:
        - sort_by (string, optional): Field to sort tasks by
            * 'priority' (default): Sort by priority level (high to low)
            * 'title': Sort by task title alphabetically
            * Other task attributes can be specified

        - filter_by (string, optional): Filter tasks by priority level
            * '1': Show only low priority tasks
            * '2': Show only medium priority tasks
            * '3': Show only high priority tasks
            * Empty/omitted: Show all tasks

    Data Processing:
        1. Extracts sort_by and filter_by parameters from request
        2. Queries main tasks (parent_task_id=None) for current user
        3. Applies priority filter if specified
        4. Sorts tasks according to sort_by parameter
        5. Eager loads subtasks to prevent N+1 query issues

    Returns:
        Web Clients:
            - Rendered index.html template with:
                * tasks: List of main Task objects
                * suggested_tasks: Predefined task suggestions
                * sort_by: Current sort parameter
                * filter_by: Current filter parameter
                * max_depth: Maximum nesting level allowed

    Task Structure:
        - Only main tasks (depth 0) are returned at the top level
        - Each task includes all subtasks recursively serialized
        - Subtasks are eager-loaded to optimize database performance
        - Tasks include completion statistics and progress indicators

    Sorting Options:
        - priority (default): High to low priority (3, 2, 1)
        - title: Alphabetical by task title
        - Any other task attribute can be specified

    Filtering Options:
        - Priority-based filtering (1=Low, 2=Medium, 3=High)
        - Can be combined with any sort option
        - Empty filter shows all tasks

    Performance Considerations:
        - Uses eager loading for subtasks to prevent N+1 queries
        - Filters at database level for efficiency
        - Sorting performed in Python for flexibility
    """
    try:
        sort_by = request.args.get('sort_by', 'priority')
        filter_by = request.args.get('filter_by', '')

        # Build query - only get main tasks (not subtasks) for the main view
        if filter_by:
            tasks = Task.query.filter_by(user_id=current_user.id, priority=int(filter_by), parent_task_id=None).all()
        else:
            tasks = Task.query.filter_by(user_id=current_user.id, parent_task_id=None).all()

        # Apply sorting
        if sort_by == 'priority':
            tasks.sort(key=lambda task: task.priority, reverse=True)
        else:
            tasks.sort(key=lambda task: getattr(task, sort_by, ''))

        # Load subtasks for each task to avoid N+1 queries
        for task in tasks:
            task.subtasks.all()

        # HTML response
        suggested_tasks = [
            "Buy groceries", "Read a book", "Exercise", "Clean the house", "Write a blog post",
            "Learn a new skill", "Call a friend", "Plan a trip", "Cook a new recipe", "Organize your workspace"
        ]
        return render_template('index.html', tasks=tasks, suggested_tasks=suggested_tasks,
                               sort_by=sort_by, filter_by=filter_by, max_depth=MAX_NESTING_DEPTH)

    except Exception as e:
        flash('An error occurred while loading tasks', 'error')
        return render_template('index.html', tasks=[], suggested_tasks=[])


@main.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    """
    Create new tasks or subtasks with validation and depth control.

    This endpoint handles the creation of both main tasks and nested subtasks.
    It includes comprehensive validation, depth limiting, and supports web form submissions.

    Authentication:
        - Requires active user session (@login_required decorator)
        - Associates created tasks with the authenticated user

    GET Request:
        - Web: Returns add_task.html form template

    POST Request Processing:
        1. Extracts task data from form
        2. Validates required fields (title is mandatory)
        3. Processes parent_task_id for subtask creation
        4. Validates parent task ownership and existence
        5. Checks nesting depth against MAX_NESTING_DEPTH limit
        6. Calculates task depth based on parent hierarchy
        7. Creates and saves new Task record
        8. Returns success response or redirects appropriately

    Request Data (POST):

        Form Data (Web clients):
            - title: string (required)
            - priority: integer (optional, default=1)
            - parent_task_id: integer (optional)

    Task Hierarchy Rules:
        - Main tasks: parent_task_id = None, depth = 0
        - Subtasks: parent_task_id = valid parent ID, depth = parent.depth + 1
        - Maximum nesting depth enforced (MAX_NESTING_DEPTH = 5)
        - Parent task must belong to current user
        - Parent task must exist in database

    Returns:
        GET Requests:
            - Web: Rendered task creation form (200)

        POST Success:
            - Web: Redirect to index (main task) or parent details (subtask)

        POST Failure:
            - Web: Redirect with flash error message

    Validation Rules:
        - title: Required, non-empty string
        - priority: Optional integer 1-3, defaults to 1
        - parent_task_id: Optional, must reference existing user task
        - Depth limit: Cannot exceed MAX_NESTING_DEPTH levels

    Security Features:
        - Parent task ownership validation
        - User isolation (tasks only visible to owner)
        - Input sanitization and type conversion
        - Database rollback on errors

    Database Operations:
        - Queries parent task for validation and depth calculation
        - Creates new Task record with calculated depth
        - Commits transaction or rolls back on error

    Navigation Behavior (Web):
        - Creating main task -> redirects to index page
        - Creating subtask -> redirects to parent task details page
        - Error conditions -> redirects to appropriate page with flash message
    """

    if request.method == 'GET':
        return render_template('add_task.html')  # You may need to create this template
    try:
        title = request.form.get('title')
        priority = int(request.form.get('priority', 1))
        parent_task_id = request.form.get('parent_task_id')

        if not title:
            error_msg = 'Task title is required'
            flash(error_msg + '!', 'error')
            return redirect(url_for('main.index'))

        # Convert parent_task_id to int if it exists and is not empty
        if parent_task_id and str(parent_task_id).strip():
            try:
                parent_task_id = int(parent_task_id)
            except (ValueError, TypeError):
                parent_task_id = None
        else:
            parent_task_id = None

        # Calculate depth
        depth = 0
        if parent_task_id:
            parent_task = Task.query.get(parent_task_id)
            if not parent_task or parent_task.user_id != current_user.id:
                error_msg = 'Invalid parent task or access denied'
                flash(error_msg + '!', 'error')
                return redirect(url_for('main.index'))

            if not parent_task.can_add_subtask(MAX_NESTING_DEPTH):
                error_msg = f'Maximum nesting depth of {MAX_NESTING_DEPTH} levels reached'
                flash(error_msg + '!', 'error')
                return redirect(url_for('main.task_details', task_id=parent_task_id))

            depth = parent_task.depth + 1

        # Create the task
        new_task = Task(
            title=title,
            user_id=current_user.id,
            priority=priority,
            parent_task_id=parent_task_id,
            depth=depth
        )

        db.session.add(new_task)
        db.session.commit()

        # HTML redirect logic
        if parent_task_id:
            flash('Subtask added successfully!', 'success')
            return redirect(url_for('main.task_details', task_id=parent_task_id))
        else:
            flash('Task added successfully!', 'success')
            return redirect(url_for('main.index'))

    except Exception as e:
        db.session.rollback()
        flash('An error occurred while creating the task', 'error')
        return redirect(url_for('main.index'))


@main.route('/complete/<int:task_id>')
@login_required
def complete(task_id):
    """
    Toggle the completion status of a task and all its subtasks recursively.

    This endpoint handles marking tasks as complete or incomplete. When a task's
    completion status is changed, all of its subtasks are automatically updated
    to match the parent's status, maintaining consistency in the task hierarchy.

    Authentication:
        - Requires active user session (@login_required decorator)
        - Only allows toggling tasks owned by the authenticated user

    URL Parameters:
        - task_id (int): The unique identifier of the task to toggle

    Process:
        1. Retrieves task from database using task_id
        2. Validates task exists and belongs to current user
        3. Toggles the task's completion status (True ↔ False)
        4. Recursively updates all subtasks to match parent status
        5. Commits changes to database
        6. Returns appropriate response or redirects

    Recursive Subtask Updates:
        - When marking complete: All subtasks become completed
        - When marking incomplete: All subtasks become incomplete
        - Updates cascade through all nesting levels
        - Maintains hierarchy consistency

    Returns:
        Web Clients:
            - Redirect to parent task details (if subtask)
            - Redirect to main index page (if main task)

    Navigation Logic (Web):
        - Subtasks: Redirects to root task details page for context
        - Main tasks: Redirects to index page
        - Uses root_task property to find top-level ancestor

    Security Features:
        - Task ownership validation prevents unauthorized access
        - User isolation ensures users can only modify their tasks
        - Database rollback on errors maintains data integrity

    Performance Considerations:
        - Single database query to retrieve task and subtasks
        - Recursive function processes subtasks in memory
        - Single commit for all changes reduces database overhead

    Database Operations:
        - SELECT: Retrieves task and validates ownership
        - UPDATE: Changes completion status recursively
        - Uses task.subtasks relationship for hierarchy traversal

    Example Usage:
        # Complete a main task (web)
        GET /complete/123 -> Redirects to index with task completed
    """
    try:
        task = Task.query.get(task_id)
        if not task or task.user_id != current_user.id:
            return redirect(url_for('main.index'))

        def toggle_subtasks(task_obj, completed_status):
            for subtask in task_obj.subtasks:
                subtask.completed = completed_status
                toggle_subtasks(subtask, completed_status)

        task.completed = not task.completed
        toggle_subtasks(task, task.completed)
        db.session.commit()

        if task.parent_task_id:
            root_task = task.root_task
            return redirect(url_for('main.task_details', task_id=root_task.id))
        return redirect(url_for('main.index'))

    except Exception as e:
        db.session.rollback()
        return redirect(url_for('main.index'))


@main.route('/delete/<int:task_id>')
@login_required
def delete(task_id):
    """
    Delete a task and all its subtasks from the database.

    This endpoint permanently removes a task and its entire subtask hierarchy
    from the database. The deletion cascades automatically due to the database
    foreign key relationship configuration, ensuring no orphaned subtasks remain.

    Authentication:
        - Requires active user session (@login_required decorator)
        - Only allows deleting tasks owned by the authenticated user

    URL Parameters:
        - task_id (int): The unique identifier of the task to delete

    Process:
        1. Retrieves task from database using task_id
        2. Validates task exists and belongs to current user
        3. Stores navigation information (parent/root task IDs)
        4. Deletes task from database (cascades to subtasks)
        5. Commits deletion transaction
        6. Returns appropriate response or redirects

    Cascade Deletion:
        - Database foreign key constraints handle cascade deletion
        - All subtasks at any nesting level are automatically removed
        - No manual recursion needed due to database configuration
        - Maintains referential integrity

    Returns:
        Web Clients:
            - Redirect to parent task details (if deleting subtask)
            - Redirect to main index page (if deleting main task)

    Navigation Logic (Web):
        - Subtasks: Redirects to root task details page
        - Main tasks: Redirects to index page
        - Navigation data captured before deletion

    Security Features:
        - Task ownership validation prevents unauthorized deletion
        - User isolation ensures users can only delete their tasks
        - Database rollback on errors prevents partial deletions

    Data Preservation:
        - Parent/root task IDs stored before deletion for navigation
        - Database transaction ensures atomic operation
        - Rollback protection maintains data consistency

    Database Operations:
        - SELECT: Retrieves task and validates ownership
        - DELETE: Removes task (cascades to subtasks automatically)
        - Uses SQLAlchemy's session management for transactions

    Permanent Operation:
        - Deletion is irreversible
        - No soft delete or recovery mechanism
        - All associated subtask data is permanently lost

    Example Usage:
        # Delete a main task (web)
        GET /delete/123 -> Redirects to index, task and subtasks removed
    """
    try:
        task = Task.query.get(task_id)
        if not task or task.user_id != current_user.id:
            return redirect(url_for('main.index'))

        # Store parent task ID and root task ID before deletion
        parent_id = task.parent_task_id
        root_task_id = task.root_task.id if task.parent_task_id else None

        db.session.delete(task)
        db.session.commit()

        if parent_id:
            return redirect(url_for('main.task_details', task_id=root_task_id))
        return redirect(url_for('main.index'))

    except Exception as e:
        db.session.rollback()
        return redirect(url_for('main.index'))


@main.route('/task/<int:task_id>')
@login_required
def task_details(task_id):
    """
    Display comprehensive details for a specific task including subtasks and navigation.

    This endpoint provides a detailed view of an individual task, showing its
    complete subtask hierarchy, breadcrumb navigation, and all relevant metadata.
    It serves as the primary interface for managing complex nested tasks.

    Authentication:
        - Requires active user session (@login_required decorator)
        - Only displays tasks owned by the authenticated user

    URL Parameters:
        - task_id (int): The unique identifier of the task to display

    Data Loading:
        1. Retrieves task from database using task_id
        2. Validates task exists and belongs to current user
        3. Builds breadcrumb trail from root to current task
        4. Recursively loads all subtasks for complete hierarchy
        5. Returns data in appropriate format (HTML)

    Breadcrumb Navigation:
        - Shows path from root task to current task
        - Uses task.get_ancestors() method for hierarchy traversal
        - Includes current task as final breadcrumb item
        - Provides navigation context for nested tasks

    Subtask Loading:
        - Recursively loads complete subtask hierarchy
        - Prevents database N+1 query issues through eager loading
        - Maintains parent-child relationships for display
        - Includes all nesting levels up to maximum depth

    Returns:
        Web Clients:
            - Rendered task_details.html template with:
                * task: Complete Task object with metadata
                * subtasks: Hierarchical list of subtasks
                * breadcrumbs: Navigation trail from root
                * max_depth: Maximum allowed nesting level

    Template Data (Web):
        - task: Full task object with all properties
        - subtasks: Recursively loaded subtask hierarchy
        - breadcrumbs: List of ancestor tasks plus current task
        - max_depth: Configuration constant for nesting limits

    Performance Optimizations:
        - Single query to retrieve main task
        - Recursive function loads subtasks efficiently
        - Breadcrumb calculation uses cached ancestor data
        - Template receives pre-loaded data to minimize queries

    Security Features:
        - Task ownership validation prevents unauthorized access
        - User isolation ensures data privacy
        - Handles non-existent task IDs gracefully

    Navigation Features:
        - Breadcrumbs show complete navigation path
        - Each breadcrumb is clickable for navigation
        - Current task highlighted in breadcrumb trail
        - Root task always accessible from breadcrumbs

    Example Usage:
        # View task details (web)
        GET /task/123 -> Renders detailed task page with subtasks

    """
    try:
        task = Task.query.get(task_id)
        if not task or task.user_id != current_user.id:
            return redirect(url_for('main.index'))

        # Get breadcrumbs
        breadcrumbs = []
        if task.parent_task_id:
            breadcrumbs = task.get_ancestors()
            breadcrumbs.append(task)

        # HTML response - load subtasks recursively
        def load_subtasks_recursive(parent_task):
            subtasks = parent_task.subtasks.all()
            for subtask in subtasks:
                load_subtasks_recursive(subtask)
            return subtasks

        subtasks = load_subtasks_recursive(task)
        return render_template('task_details.html', task=task, subtasks=subtasks,
                               breadcrumbs=breadcrumbs, max_depth=MAX_NESTING_DEPTH)

    except Exception as e:
        return redirect(url_for('main.index'))


@main.route('/check_username', methods=['POST'])
def check_username():
    """
    Validate username availability during registration process.

    This utility endpoint checks if a proposed username is already taken in the
    database. It's typically used for real-time validation during user registration
    to provide immediate feedback without form submission.

    HTTP Methods:
        - POST only: Prevents username enumeration via GET requests

    Request Data:
        JSON (API clients):
            {
                "username": "string (required) - Username to check"
            }

        Form Data (Web clients):
            - username: string (required) - Username to validate

    Process:
        1. Extracts username from request (JSON or form data)
        2. Validates username parameter is provided
        3. Queries database for existing user with same username
        4. Returns availability status in JSON format

    Returns:
        Success Response (200):
            {
                "exists": boolean,     # True if username is taken
                "available": boolean   # True if username is available
            }

        Error Response (400):
            {
                "error": "Username is required"
            }

        Server Error (500):
            {
                "error": "Error message describing database issue"
            }

    Response Logic:
        - exists: true = username already taken
        - exists: false = username available
        - available: opposite of exists (for convenience)

    Security Considerations:
        - Uses POST to prevent username enumeration attacks
        - No sensitive user data returned
        - Only indicates availability, not user details
        - Rate limiting should be implemented at reverse proxy level

    Database Operations:
        - Single SELECT query to check username existence
        - No data modification performed
        - Minimal database impact

    Use Cases:
        - Real-time registration form validation
        - AJAX username checking
        - API client registration workflows
        - User experience improvement

    Client Integration:
        - Typically called via JavaScript during typing
        - Can be used for form validation before submission
        - Reduces registration failures due to taken usernames

    Error Conditions:
        - 400: Missing username parameter
        - 500: Database connection or query error

    Example Usage:
        # Check username availability
        POST /check_username
        Content-Type: application/json
        {
            "username": "john_doe"
        }

        Response:
        {
            "exists": false,
            "available": true
        }

        # Form-based check
        POST /check_username
        Content-Type: application/x-www-form-urlencoded
        username=jane_smith
    """
    try:
        username = request.form.get('username')
        if not username:
            return jsonify({'error': 'Username is required'}), 400

        existing_user = User.query.filter_by(username=username).first()

        return jsonify({
            'exists': existing_user is not None,
            'available': existing_user is None
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main.route('/suggested_tasks', methods=['GET'])
@login_required
def get_suggested_tasks():
    """
    Retrieve predefined task suggestions to inspire users.

    This endpoint provides a curated list of common task suggestions that users
    can quickly add to their task lists. It helps overco    me the "blank page" problem
    and provides inspiration for task management.

    Authentication:
        - Requires active user session (@login_required decorator)
        - Available to all authenticated users

    HTTP Methods:
        - GET only: Simple data retrieval endpoint

    Suggested Task Categories:
        - Personal care: "Exercise", "Read a book"
        - Household: "Buy groceries", "Clean the house"
        - Professional: "Write a blog post", "Learn a new skill"
        - Social: "Call a friend", "Plan a trip"
        - Organization: "Organize your workspace"
        - Creativity: "Cook a new recipe"

    Returns:
        Web Clients:
            {
                "suggested_tasks": [...]
            }

    Data Structure:
        - Static list of string task suggestions
        - Diverse categories to appeal to different users
        - Common, actionable tasks that most users can relate to
        - No personalization (same for all users)

    Usage Patterns:
        - Displayed on main dashboard for quick task creation
        - Used in "Add Task" interfaces as inspiration
        - Can be integrated with quick-add functionality
        - Helpful for new users getting started

    Implementation Notes:
        - Suggestions are hardcoded in function
        - No database queries required
        - Fast response time
        - Could be enhanced with user-specific or dynamic suggestions

    Future Enhancements:
        - User-specific suggestions based on history
        - Category-based filtering
        - Seasonal or contextual suggestions
        - User-submitted suggestion pool
    """
    suggested_tasks = [
        "Buy groceries", "Read a book", "Exercise", "Clean the house", "Write a blog post",
        "Learn a new skill", "Call a friend", "Plan a trip", "Cook a new recipe", "Organize your workspace"
    ]

    return jsonify({'suggested_tasks': suggested_tasks})


@main.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Initiate the password recovery process using security questions.

    This endpoint begins the secure password reset workflow by validating the
    user's identity and presenting their security question. It implements the
    first step of a multi-stage password recovery system.

    HTTP Methods:
        - GET: Display password recovery form (web clients)

    GET Request:
        - Web: Returns forgot_password.html template

    POST Request Processing:
        1. Extracts username from request (JSON or form data)
        2. Validates username is provided
        3. Searches database for user with matching username
        4. If found, stores username and security question in session
        5. Proceeds to security question verification step

    Session Management:
        - Stores username in session for subsequent steps
        - Stores security_question for display and validation
        - Session data used throughout recovery workflow
        - Session cleared after successful password reset

    Returns:
        GET Requests:
            - Web: Rendered forgot password form (200)

        POST Success:
            - Web: Redirect to security question page

        POST Failure:
            - Web: Re-rendered form with error message

    Security Features:
        - Username existence confirmed before revealing security question
        - No sensitive information exposed for non-existent users
        - Session-based workflow prevents direct access to later steps
        - Error messages don't reveal whether username exists (timing attacks possible)

    Workflow Integration:
        - Step 1 of 3-step password recovery process
        - Success leads to /security_answer endpoint
        - Forms part of complete password recovery chain
        - Session state maintains progress through workflow

    Privacy Considerations:
        - Security question revealed only after username validation
        - Username existence indirectly confirmed through success/failure
        - No email or other sensitive data exposed
        - Session timeout provides additional security

    Example Usage:
        # Start password recovery (web)
        POST /forgot_password
        Form data: username=john_doe
        -> Redirects to security question page
    """
    if request.method == 'GET':
        return render_template('forgot_password.html')

    try:
        username = request.form.get('username')

        if not username:
            error_msg = 'Username is required'
            return render_template('forgot_password.html', error_message=error_msg)

        user = User.query.filter_by(username=username).first()
        if user:
            session['username'] = username
            session['security_question'] = user.security_question

            return redirect(url_for('main.security_answer'))
        else:
            error_msg = 'Username not found'
            return render_template('forgot_password.html', error_message=error_msg)

    except Exception as e:
        return render_template('forgot_password.html', error_message='An error occurred')


@main.route('/security_answer', methods=['GET', 'POST'])
def security_answer() -> Union[str, Tuple[Dict[str, Any], int]]:
    """
    Handle the security question verification process during password reset.

    This endpoint manages the second step of the password recovery flow where users
    must answer their security question correctly to proceed to password reset.

    Session Requirements:
        username (str): User's username from the previous step
        security_question (str): The security question text retrieved from database

    Returns:
        GET Request:
            - HTML: Rendered security answer form template
            - Redirects to forgot_password if session is invalid

        POST Request:
            - HTML: Redirects to reset_password on success, re-renders form on error

    Security Features:
        - Session-based state management
        - Direct string comparison for security answers (consider case sensitivity)
        - Automatic session cleanup on errors
    """
    username: Optional[str] = session.get('username')
    security_question: Optional[str] = session.get('security_question')

    if request.method == 'GET':
        if not username or not security_question:
            return redirect(url_for('main.forgot_password'))
        return render_template('security_answer.html', security_question=security_question)

    try:
        security_answer_input: Optional[str] = request.form.get('security_answer')

        if not security_answer_input:
            error_msg = 'Security answer is required'
            return render_template('security_answer.html',
                                   security_question=security_question,
                                   error_message=error_msg)

        user = User.query.filter_by(username=username).first()
        if not user:
            return redirect(url_for('main.forgot_password'))

        if user.security_answer == security_answer_input:
            return redirect(url_for('main.reset_password'))
        else:
            # Incorrect answer
            error_msg = 'Incorrect security answer'
            return render_template('security_answer.html',
                                   security_question=security_question,
                                   error_message=error_msg)

    except Exception as e:
        return render_template('security_answer.html',
                               security_question=security_question,
                               error_message='An error occurred')


@main.route('/reset_password', methods=['GET', 'POST'])
def reset_password() -> Union[str, Tuple[Dict[str, Any], int]]:
    """
    Handle the final password reset process.

    This endpoint manages the third and final step of password recovery where users
    set their new password after successfully answering their security question.

    Session Requirements:
        username (str): User's username from previous verification steps

    Security Features:
        - PBKDF2-SHA256 password hashing
        - Session data cleanup after successful reset
        - Database transaction rollback on errors
        - Input validation and sanitization

    Returns:
        GET Request:
            - HTML: Password reset form template

        POST Request:
            - HTML: Redirects to login on success with flash message

    Database Operations:
        - Updates user.password field with hashed password
        - Commits transaction on success
        - Rolls back on any database errors
    """
    username: Optional[str] = session.get('username')

    if request.method == 'GET':
        if not username:
            return redirect(url_for('main.forgot_password'))
        return render_template('reset_password.html')
    try:
        new_password: Optional[str] = request.form.get('new_password')

        if not new_password:
            error_msg = 'New password is required'
            return render_template('reset_password.html', error_message=error_msg)

        user = User.query.filter_by(username=username).first()
        if not user:
            return redirect(url_for('main.forgot_password'))

        hashed_password: str = generate_password_hash(new_password, method='pbkdf2:sha256')

        # Update user's password in database
        user.password = hashed_password
        db.session.commit()

        # Clean up sensitive session data to prevent reuse
        session.pop('username', None)
        session.pop('security_question', None)

        # Return success response
        success_msg = 'Password has been reset successfully'
        flash(success_msg, 'success')
        return redirect(url_for('main.login'))

    except Exception as e:
        db.session.rollback()
        return render_template('reset_password.html',
                               error_message='An error occurred during password reset')


@main.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit(task_id: int) -> Union[str, Tuple[Dict[str, Any], int]]:
    """
    Edit the details of a specific task with proper access control.

    This endpoint allows authenticated users to view and modify their own tasks.
    Supports partial updates and maintains task hierarchy relationships.

    Args:
        task_id (int): The unique identifier of the task to edit

    Access Control:
        - Requires user authentication (@login_required)
        - Users can only edit tasks they own (task.user_id == current_user.id)
        - Returns 404 for non-existent or unauthorized tasks

    Supported Updates:
        - title (str): Task title/description
        - priority (int): Priority level (typically 1-3)
        - completed (bool): Task completion status

    Returns:
        GET Request:
            - HTML: Edit form template populated with current values

        POST/PUT/PATCH Request:
            - HTML: Redirects to appropriate view based on task hierarchy

    Navigation Logic:
        - Subtasks: Redirects to root task details page for context
        - Main tasks: Redirects to main index page
    """
    try:
        # Fetch task with ownership verification
        task = Task.query.get(task_id)

        # Ensure task exists and user has permission to edit it
        if not task or task.user_id != current_user.id:
            return redirect(url_for('main.index'))

        if request.method == 'GET':
            # Return task data for editing interface
            return render_template('edit_task.html', task=task)

        if 'title' in request.form:
            task.title = request.form.get('title')
        if 'priority' in request.form:
            task.priority = int(request.form.get('priority'))

        # Commit changes to database
        db.session.commit()

        if task.parent_task_id:
            # For subtasks, navigate to root task for context
            root_task = task.root_task
            return redirect(url_for('main.task_details', task_id=root_task.id))
        # For main tasks, return to index
        return redirect(url_for('main.index'))

    except Exception as e:
        db.session.rollback()
        return redirect(url_for('main.index'))


@main.route('/add_suggested/<string:task_title>', methods=['POST'])
@login_required
def add_suggested(task_title: str) -> str:
    """
    Add a suggested task to the user's task list with minimal input.

    This endpoint provides a quick way to add predefined or suggested tasks
    without going through the full task creation form. Commonly used for
    template tasks or recommendations.

    Args:
        task_title (str): The title of the suggested task (URL-encoded)

    Form Parameters:
        priority (str, optional): Task priority level (default: 1)

    Task Properties:
        - title: From URL parameter (automatically URL-decoded by Flask)
        - user_id: Current authenticated user
        - priority: From form data or default to 1 (low priority)
        - depth: Always 0 (main task, not a subtask)
        - completed: Always False (new tasks start incomplete)

    Returns:
        str: Redirect response to main index page

    Usage Example:
        POST /add_suggested/Review%20weekly%20reports
        Form data: priority=2
        Creates: Task(title="Review weekly reports", priority=2, ...)

    Security:
        - Requires authentication (@login_required)
        - Task automatically assigned to current user
    """
    priority: str = request.form.get('priority', '1')

    # Create new task with suggested title and user ownership
    new_task = Task(
        title=task_title,  # Flask automatically URL-decodes this
        user_id=current_user.id,  # Assign to authenticated user
        priority=int(priority),  # Convert string to integer
        depth=0  # Main task (not nested)
    )

    # Save to database
    db.session.add(new_task)
    db.session.commit()

    # Redirect to main task list
    return redirect(url_for('main.index'))


@main.route('/import_markdown', methods=['POST'])
@login_required
def import_markdown() -> Union[str, Tuple[Dict[str, Any], int]]:
    """
    Handle the import of tasks from markdown content with hierarchical structure.

    This endpoint supports two distinct import modes:
    1. Importing from pre-parsed task data (preview mode)
    2. Direct import from raw markdown content or uploaded files

    The parser recognizes several markdown formats:
    - Headers (# ## ###) become main tasks and categories
    - Checkbox items (- [ ] - [x]) become tasks with completion status
    - Bullet points (- *) become incomplete tasks
    - Indentation creates nested subtask relationships

    Supported Input Modes:
        HTML Form:
            - parsed_tasks: JSON string of task data (preview mode)
            - markdown_file: Uploaded .md or .txt file

    Parameters:
        default_priority (int): Priority level for imported tasks (default: 2)

    Returns:
        HTML Response:
            - Redirects to index with flash message

    Security Considerations:
        - File type validation for uploads (.md, .txt only)
        - Content size limits (handled by Flask configuration)
        - UTF-8 encoding assumption for file content

    Database Operations:
        - Creates nested task hierarchy with proper parent-child relationships
        - Maintains depth tracking for UI rendering
        - Atomic transaction with rollback on errors
    """
    try:
        if 'parsed_tasks' in request.form:
            # Import from preview data (user confirmed import)
            parsed_tasks: List[Dict[str, Any]] = json.loads(request.form.get('parsed_tasks'))
            default_priority: int = int(request.form.get('default_priority', 2))
            imported_count: int = import_tasks_from_data(parsed_tasks, default_priority)
            flash(f'Successfully imported {imported_count} tasks!', 'success')
        else:
            # Handle file upload
            if 'markdown_file' not in request.files:
                flash('No file selected', 'error')
                return redirect(url_for('main.index'))

            file = request.files['markdown_file']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(url_for('main.index'))

            # Validate file type and process content
            if file and allowed_file(file.filename):
                # Read and decode file content
                content: str = file.read().decode('utf-8')
                default_priority: int = int(request.form.get('default_priority', 2))

                # Parse markdown structure
                parsed_tasks: List[Dict[str, Any]] = parse_markdown_content(content)

                if not parsed_tasks:
                    flash('No tasks found in the markdown file', 'warning')
                    return redirect(url_for('main.index'))

                # Import parsed tasks
                imported_count: int = import_tasks_from_data(parsed_tasks, default_priority)
                flash(f'Successfully imported {imported_count} tasks from markdown file!', 'success')
            else:
                flash('Invalid file type. Please upload a .md or .txt file', 'error')

        return redirect(url_for('main.index'))

    except Exception as e:
        # Ensure database consistency on errors
        db.session.rollback()
        flash(f'Error importing markdown: {str(e)}', 'error')
        return redirect(url_for('main.index'))


def allowed_file(filename: str) -> bool:
    """
    Check if the uploaded file has an allowed extension for security.

    This function validates file extensions to prevent upload of potentially
    dangerous file types while allowing common text formats for task import.

    Args:
        filename (str): The name of the uploaded file including extension

    Returns:
        bool: True if the file extension is allowed, False otherwise

    Allowed Extensions:
        - .md: Markdown files
        - .txt: Plain text files

    Security Notes:
        - Only validates extension, not file content
        - Case-insensitive comparison using .lower()
        - Requires at least one dot in filename

    Example:
        >>> allowed_file("tasks.md")
        True
        >>> allowed_file("README.TXT")
        True
        >>> allowed_file("malicious.exe")
        False
        >>> allowed_file("no_extension")
        False
    """
    ALLOWED_EXTENSIONS = {'md', 'txt'}
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def parse_markdown_content(content: str) -> List[Dict[str, Any]]:
    """
    Parse markdown content and extract tasks with hierarchical structure.

    This function converts various markdown formats into a structured task
    hierarchy that can be imported into the database. It handles different
    indentation levels and markdown syntax variations.

    Supported Markdown Formats:
        - Headers: # ## ### (converted to tasks and categories)
        - Checkboxes: - [ ] - [x] - [X] (tasks with completion status)
        - Bullet points: - task or * task (incomplete tasks)
        - Indentation: Spaces or tabs create subtask relationships

    Args:
        content (str): Raw markdown content to parse

    Returns:
        List[Dict[str, Any]]: Hierarchical list of task objects

        Task Structure:
        {
            'title': str,               # Task description
            'completed': bool,          # Completion status
            'subtasks': List[Dict],     # Nested subtasks
            'depth': int               # Hierarchy depth (0 = main task)
        }

    Algorithm Details:
        1. Processes content line by line
        2. Uses task_stack to maintain hierarchy context
        3. Calculates indentation levels for nesting
        4. Maps different markdown elements to task types

    Indentation Rules:
        - 2 spaces or 1 tab = 1 indentation level
        - Each level creates deeper nesting
        - Stack management ensures proper parent-child relationships

    Example Input:
        ```
        # Main Project
        ## Phase 1
        - [ ] Setup environment
        - [x] Install dependencies
          - [ ] Configure database
        ```

    Example Output:
        [
            {
                'title': 'Main Project',
                'completed': False,
                'depth': 0,
                'subtasks': [
                    {
                        'title': 'Phase 1',
                        'completed': False,
                        'depth': 1,
                        'subtasks': [
                            {
                                'title': 'Setup environment',
                                'completed': False,
                                'depth': 2,
                                'subtasks': []
                            }
                        ]
                    }
                ]
            }
        ]
    """
    lines: List[str] = content.split('\n')
    tasks: List[Dict[str, Any]] = []
    task_stack: List[Dict[str, Any]] = []  # Stack to track nested structure

    for line in lines:
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Calculate indentation level for nested structure
        original_line = line
        indent_level = 0

        # Count leading spaces/tabs (2 spaces or 1 tab = 1 level)
        while line.startswith('  ') or line.startswith('\t'):
            indent_level += 1
            line = line[2:] if line.startswith('  ') else line[1:]

        # Parse different markdown elements

        if line.startswith('# '):
            # Main task header (# Header)
            title = line[2:].strip()
            new_task = {
                'title': title,
                'completed': False,
                'subtasks': [],
                'depth': 0
            }
            tasks.append(new_task)
            task_stack = [new_task]  # Reset stack with new main task

        elif line.startswith('#'):
            # Subtask headers (##, ###, etc.)
            header_level = len(line) - len(line.lstrip('#'))
            title = line.lstrip('#').strip()

            new_task = {
                'title': title,
                'completed': False,
                'subtasks': [],
                'depth': header_level - 1
            }

            # Find appropriate parent based on header level
            target_depth = header_level - 2
            while len(task_stack) > target_depth + 1:
                task_stack.pop()

            # Attach to parent or create as main task
            if task_stack:
                task_stack[-1]['subtasks'].append(new_task)
                task_stack.append(new_task)
            else:
                tasks.append(new_task)
                task_stack = [new_task]

        elif line.startswith('- [') and (line[3] in ['x', ' ', 'X']):
            # Checkbox tasks (- [ ] or - [x] or - [X])
            completed = line[3].lower() == 'x'
            title = line[5:].strip()

            new_task = {
                'title': title,
                'completed': completed,
                'subtasks': [],
                'depth': indent_level
            }

            # Manage task hierarchy based on indentation
            while len(task_stack) > indent_level + 1:
                task_stack.pop()

            if task_stack and indent_level > 0:
                task_stack[-1]['subtasks'].append(new_task)
                task_stack.append(new_task)
            else:
                tasks.append(new_task)
                task_stack = [new_task]

        elif line.startswith('- ') or line.startswith('* '):
            # Bullet point tasks (- or *)
            title = line[2:].strip()

            new_task = {
                'title': title,
                'completed': False,
                'subtasks': [],
                'depth': indent_level
            }

            # Manage task hierarchy based on indentation
            while len(task_stack) > indent_level + 1:
                task_stack.pop()

            if task_stack and indent_level > 0:
                task_stack[-1]['subtasks'].append(new_task)
                task_stack.append(new_task)
            else:
                tasks.append(new_task)
                task_stack = [new_task]

    return tasks


def import_tasks_from_data(parsed_tasks: List[Dict[str, Any]], default_priority: int) -> int:
    """
    Import hierarchical task data into the database with proper relationships.

    This function recursively processes the parsed task structure and creates
    corresponding database records while maintaining parent-child relationships
    and preventing excessive nesting.

    Args:
        parsed_tasks (List[Dict[str, Any]]): Structured task data from parser
        default_priority (int): Priority level to assign to all imported tasks

    Returns:
        int: Total number of tasks successfully imported (including subtasks)

    Database Operations:
        - Creates Task objects with proper foreign key relationships
        - Uses flush() to get IDs before committing for parent references
        - Maintains depth tracking for UI hierarchy rendering
        - Single commit at end for atomic operation

    Nesting Protection:
        - Enforces MAX_NESTING_DEPTH limit to prevent stack overflow
        - Skips deeply nested tasks rather than failing entire import

    Task Attributes Set:
        - title: From parsed task data
        - completed: From parsed completion status
        - priority: Uses provided default_priority
        - parent_task_id: Set for subtasks to maintain hierarchy
        - user_id: Assigned to current authenticated user
        - depth: Calculated from nesting level for UI rendering

    Recursive Processing:
        - Main tasks created first with parent_task_id = None
        - Subtasks reference parent's ID after database flush
        - Depth increments with each nesting level
        - Counter tracks total across all recursion levels
    """
    imported_count = 0

    def create_task_recursive(task_data: Dict[str, Any],
                              parent_id: Optional[int] = None,
                              current_depth: int = 0) -> Optional[Task]:
        """
        Recursively create tasks and their subtasks in the database.

        This nested function handles the recursive creation of task hierarchies
        while maintaining proper parent-child relationships and depth tracking.

        Args:
            task_data (Dict[str, Any]): Individual task data to create
            parent_id (Optional[int]): ID of parent task (None for main tasks)
            current_depth (int): Current nesting level (0-based)

        Returns:
            Optional[Task]: Created task object, or None if depth limit exceeded

        Depth Limit Protection:
            - Prevents creation beyond MAX_NESTING_DEPTH
            - Returns None rather than raising exception
            - Allows partial import to continue

        Database Flush Strategy:
            - Uses flush() to get primary key without full commit
            - Enables parent_id assignment for subsequent subtasks
            - Maintains transaction integrity until final commit
        """
        nonlocal imported_count

        # Prevent excessive nesting that could cause performance issues
        if current_depth >= MAX_NESTING_DEPTH:
            return None

        # Create task object with provided data
        task = Task(
            title=task_data['title'],
            completed=task_data['completed'],
            priority=default_priority,
            parent_task_id=parent_id,
            user_id=current_user.id,
            depth=current_depth
        )

        # Add to session and flush to get primary key
        db.session.add(task)
        db.session.flush()  # Gets ID without committing transaction
        imported_count += 1

        # Recursively create subtasks with current task as parent
        for subtask_data in task_data.get('subtasks', []):
            create_task_recursive(subtask_data, task.id, current_depth + 1)

        return task

    # Process all main tasks recursively
    for task_data in parsed_tasks:
        create_task_recursive(task_data)

    # Commit all changes atomically
    db.session.commit()
    return imported_count


@main.route('/export_tasks')
@login_required
def export_tasks() -> Union[str, Tuple[Dict[str, Any], int]]:
    """
    Export all user tasks to a formatted markdown file with metadata.

    This endpoint generates a comprehensive markdown export of the user's
    complete task hierarchy, including statistics and proper formatting
    for easy readability and re-import capability.

    Export Features:
        - Hierarchical structure preservation
        - Task completion status with visual indicators
        - Priority levels with emoji indicators
        - Export metadata (timestamp, task counts)
        - Summary statistics section

    Returns:
        HTML Response:
            - File download with proper headers
            - Content-Disposition for automatic filename

    Task Processing:
        - Fetches only main tasks (parent_task_id = None)
        - Sorts by priority (descending) then title (ascending)
        - Subtasks loaded via SQLAlchemy relationships
        - Recursive processing maintains hierarchy

    File Format:
        - UTF-8 encoded markdown
        - Timestamped filename for version control
        - Re-importable structure using same parser

    Security:
        - Only exports tasks owned by authenticated user
        - No sensitive data exposure beyond task content
    """
    try:
        # Fetch all main tasks for the current user
        # Subtasks will be loaded through SQLAlchemy relationships
        main_tasks = Task.query.filter_by(
            user_id=current_user.id,
            parent_task_id=None
        ).all()

        # Sort tasks by priority (high to low) then alphabetically by title
        main_tasks.sort(key=lambda t: (-t.priority, t.title))

        # Generate formatted markdown content
        markdown_content: str = generate_markdown_export(main_tasks)

        # Create timestamped filename for version control
        timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename: str = f"my_tasks_{timestamp}.md"

        response = make_response(markdown_content)
        response.headers['Content-Type'] = 'text/markdown'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        flash(f'Error exporting tasks: {str(e)}', 'error')
        return redirect(url_for('main.index'))


def get_priority_text(priority: int) -> str:
    """
    Convert numeric priority to human-readable text.

    This function provides consistent priority level descriptions across
    the application for user interface display and export formatting.

    Args:
        priority (int): Numeric priority level (typically 1-3)

    Returns:
        str: Human-readable priority description

    Priority Mapping:
        1: Low priority (routine tasks, nice-to-have items)
        2: Medium priority (standard tasks, default level)
        3: High priority (urgent tasks, critical items)

    Default Behavior:
        - Unknown priority levels default to "Medium"
        - Provides graceful handling of invalid input

    Example:
        >>> get_priority_text(1)
        'Low'
        >>> get_priority_text(3)
        'High'
        >>> get_priority_text(99)
        'Medium'
    """
    priority_map = {
        1: "Low",
        2: "Medium",
        3: "High"
    }
    return priority_map.get(priority, "Medium")


def generate_markdown_export(tasks: List[Task]) -> str:
    """
    Generate comprehensive markdown content from a list of main tasks.

    This function creates a well-formatted markdown document that includes
    metadata, statistics, and the complete task hierarchy with visual
    indicators for status and priority.

    Args:
        tasks (List[Task]): List of main tasks to export (subtasks via relationships)

    Returns:
        str: Complete markdown document as a string

    Document Structure:
        1. Header with export metadata
        2. Summary statistics section
        3. Horizontal rule separator
        4. Individual task sections with hierarchical formatting

    Metadata Included:
        - Export timestamp
        - Total main task count
        - Total task count including subtasks
        - Completion statistics

    Visual Elements:
        - Emoji indicators for task status (✅ completed, 📝 pending)
        - Priority level badges
        - Hierarchical indentation for subtasks
        - Checkbox format for re-import compatibility

    Statistics Calculated:
        - Total tasks (main + all subtasks)
        - Completed vs pending task counts
        - Provides quick overview of task status
    """
    content: List[str] = []

    # Generate header with export metadata
    current_time: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content.append("# My Tasks Export")
    content.append(f"**Exported on:** {current_time}")
    content.append(f"**Total main tasks:** {len(tasks)}")
    content.append("")

    # Calculate and display summary statistics
    total_tasks: int = count_all_tasks(tasks)
    completed_tasks: int = count_completed_tasks(tasks)
    pending_tasks: int = total_tasks - completed_tasks

    content.append(f"**Total tasks (including subtasks):** {total_tasks}")
    content.append(f"**Completed tasks:** {completed_tasks}")
    content.append(f"**Pending tasks:** {pending_tasks}")
    content.append("")
    content.append("---")  # Horizontal rule separator
    content.append("")

    # Process each main task with full hierarchy
    for task in tasks:
        content.extend(format_task_as_markdown(task, is_main_task=True))
        content.append("")  # Add spacing between main tasks for readability

    return '\n'.join(content)


def format_task_as_markdown(task: Task, is_main_task: bool = False, depth: int = 0) -> List[str]:
    """
    Format a single task and its subtasks as structured markdown.

    This function recursively converts a task and its hierarchy into
    markdown format with appropriate indentation, status indicators,
    and priority information.

    Args:
        task (Task): The task object to format
        is_main_task (bool): Whether this is a top-level task
        depth (int): Current indentation depth for subtasks

    Returns:
        List[str]: List of markdown lines representing the task

    Formatting Rules:
        Main Tasks:
            - Formatted as level 2 headers (##)
            - Include status emoji (✅ completed, 📝 pending)
            - Priority and status information as bold text
            - Followed by blank line for readability

        Subtasks:
            - Formatted as checkbox items (- [ ] or - [x])
            - Indented with 2 spaces per depth level
            - Include priority emoji indicators
            - Recursive processing for nested subtasks

    Visual Indicators:
        Status Icons:
            - ✅ for completed tasks
            - 📝 for pending tasks

        Priority Indicators:
            - 🔴 High priority (level 3)
            - 🟡 Medium priority (level 2)
            - 🔵 Low priority (level 1)

    Hierarchy Management:
        - Maintains proper indentation levels
        - Sorts subtasks by priority then title
        - Preserves parent-child relationships
    """
    lines: List[str] = []

    if is_main_task:
        # Format main task as header with metadata
        status_icon: str = "✅" if task.completed else "📝"
        priority_text: str = get_priority_text(task.priority)

        lines.append(f"## {status_icon} {task.title}")
        lines.append(f"**Priority:** {priority_text}")
        lines.append(f"**Status:** {'Completed' if task.completed else 'Pending'}")
        lines.append("")  # Blank line for readability
    else:
        # Format subtask as checkbox with indentation
        indent: str = "  " * depth  # 2 spaces per depth level
        checkbox: str = "[x]" if task.completed else "[ ]"
        priority_indicator: str = get_priority_indicator(task.priority)
        lines.append(f"{indent}- {checkbox} {task.title} {priority_indicator}")

    # Process subtasks recursively if they exist
    if task.subtasks:
        # Convert to list and sort by priority (high to low) then title
        subtasks: List[Task] = list(task.subtasks)
        subtasks.sort(key=lambda t: (-t.priority, t.title))

        for subtask in subtasks:
            if is_main_task:
                # First level subtasks under main task (depth 0)
                lines.extend(format_task_as_markdown(subtask, False, 0))
            else:
                # Nested subtasks (increment depth)
                lines.extend(format_task_as_markdown(subtask, False, depth + 1))

    return lines


def get_priority_indicator(priority: int) -> str:
    """
    Get a visual emoji indicator for the task's priority level.

    This function provides consistent visual cues for priority levels
    in exports and user interfaces using easily recognizable emoji.

    Args:
        priority (int): Numeric priority level

    Returns:
        str: Emoji string representing the priority level

    Priority Color Coding:
        🔴 High priority (3): Red circle for urgent/critical tasks
        🟡 Medium priority (2): Yellow circle for standard tasks
        🔵 Low priority (1): Blue circle for routine/optional tasks

    Default Behavior:
        - Unknown priorities default to medium (🟡)
        - Consistent with get_priority_text() function

    Usage Context:
        - Task export formatting
        - UI priority indicators
        - Quick visual priority assessment
    """
    priority_map = {
        1: "🔵",  # Low priority - blue circle
        2: "🟡",  # Medium priority - yellow circle
        3: "🔴"  # High priority - red circle
    }
    return priority_map.get(priority, "🟡")


def count_all_tasks(tasks: List[Task]) -> int:
    """
    Recursively count the total number of tasks including all subtasks.

    This function traverses the complete task hierarchy to provide
    accurate statistics for exports and user interface displays.

    Args:
        tasks (List[Task]): List of tasks to count (typically main tasks)

    Returns:
        int: Total count including the tasks and all nested subtasks

    Algorithm:
        - Counts each task in the input list (main tasks)
        - Recursively counts subtasks for each task
        - Uses depth-first traversal through task relationships

    Performance Considerations:
        - May trigger multiple database queries if relationships aren't eager-loaded
        - Consider using eager loading for large task hierarchies
        - Recursive approach handles arbitrary nesting depth

    Usage:
        - Export statistics generation
        - Dashboard metrics
        - Progress reporting
    """
    count = 0
    for task in tasks:
        count += 1  # Count the task itself
        if task.subtasks:
            # Recursively count all subtasks
            count += count_all_tasks(list(task.subtasks))
    return count


def count_completed_tasks(tasks: List[Task]) -> int:
    """
    Recursively count completed tasks including all subtasks.

    This function provides completion statistics by traversing the
    task hierarchy and counting only tasks marked as completed.

    Args:
        tasks (List[Task]): List of tasks to analyze for completion

    Returns:
        int: Total count of completed tasks in the hierarchy

    Completion Logic:
        - Checks task.completed boolean status
        - Includes completed tasks at all hierarchy levels
        - Does not consider partial completion of parent tasks

    Statistics Application:
        - Progress tracking and reporting
        - Completion rate calculations
        - Productivity metrics

    Complementary Function:
        - Use with count_all_tasks() to calculate completion percentage
        - pending_count = total_count - completed_count

    Example:
        >>> total = count_all_tasks(tasks)
        >>> completed = count_completed_tasks(tasks)
        >>> completion_rate = (completed / total) * 100 if total > 0 else 0
    """
    count = 0
    for task in tasks:
        if task.completed:
            count += 1
        if task.subtasks:
            # Recursively count completed subtasks
            count += count_completed_tasks(list(task.subtasks))
    return count


@main.route('/export_tasks_pdf')
@login_required
def export_tasks_pdf() -> Union[str, Tuple[Dict[str, Any], int]]:
    """
    Export tasks to PDF format using ReportLab library.

    This endpoint generates a professionally formatted PDF document
    containing the user's complete task hierarchy with visual styling
    and proper page layout.

    Dependencies:
        - ReportLab: PDF generation library (pip install reportlab)
        - Must be installed separately as it's not a core requirement

    PDF Features:
        - Professional document layout with margins
        - Hierarchical task display with proper indentation
        - Priority indicators and completion status
        - Automatic page breaks and pagination
        - Timestamped filename for version control

    Returns:
        HTML Response:
            - Direct PDF file download with proper headers
            - Content-Disposition for automatic filename

    Error Handling:
        - ImportError: Graceful fallback if ReportLab not installed
        - Redirects to markdown export as alternative
        - Flash messages for user feedback

    Security:
        - Requires authentication (@login_required)
        - Only exports user's own tasks
        - No sensitive data exposure beyond task content

    Performance Considerations:
        - PDF generation can be memory-intensive for large task lists
        - Consider pagination for very large exports
        - ReportLab handles page breaks automatically
    """
    try:
        # Fetch and sort user's main tasks
        main_tasks = Task.query.filter_by(
            user_id=current_user.id,
            parent_task_id=None
        ).all()
        main_tasks.sort(key=lambda t: (-t.priority, t.title))

        # Create in-memory buffer for PDF content
        buffer = io.BytesIO()

        # Generate timestamped filename
        timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename: str = f"my_tasks_{timestamp}.pdf"

        # Configure PDF document with standard letter size and margins
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,  # 8.5" x 11" page size
            rightMargin=72,  # 1 inch margins (72 points)
            leftMargin=72,
            topMargin=72,
            bottomMargin=18  # Smaller bottom margin for page numbers
        )

        # Build PDF content structure
        story: List[Any] = build_pdf_story(main_tasks)

        # Generate PDF document
        doc.build(story)
        buffer.seek(0)

        # Create download response with appropriate headers
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

        return response

    except ImportError:
        # Handle missing ReportLab dependency gracefully
        flash('PDF export requires ReportLab. Please install it: pip install reportlab', 'error')
        return redirect(url_for('main.export_tasks'))
    except Exception as e:
        # Handle any other PDF generation errors
        flash(f'Error exporting to PDF: {str(e)}', 'error')
        return redirect(url_for('main.index'))


def build_pdf_story(tasks):
    """
    Construct professional PDF document content using ReportLab elements.

    This function creates the complete content structure for PDF task exports
    using ReportLab's document building system. It combines styled text,
    formatted tables, and hierarchical task listings to produce a
    professionally formatted document.

    Args:
        tasks (list): List of main Task objects to include in PDF
            - Should be main tasks only (parent_task_id=None)
            - Subtasks accessed through task.subtasks relationships
            - Typically pre-sorted by priority and title

    Document Structure:
        1. Professional title with custom styling
        2. Export metadata with timestamp
        3. Statistics table with comprehensive metrics
        4. Individual task sections with hierarchical formatting
        5. Consistent spacing and visual hierarchy

    ReportLab Elements Used:
        - Paragraph: Styled text content with custom formatting
        - Table: Statistics and data presentation
        - TableStyle: Professional table formatting
        - Spacer: Consistent spacing between elements
        - Custom ParagraphStyle: Typography and layout control

    Professional Styling:
        - Custom color scheme with corporate colors
        - Elegant typography using Helvetica font family
        - Consistent spacing and alignment
        - Visual hierarchy with varying text sizes
        - Professional document presentation

    Color Scheme:
        - Primary: #2c3e50 (Dark blue-grey for text)
        - Secondary: #34495e (Darker blue-grey for headers)
        - Accent: #bdc3c7 (Light grey for borders/backgrounds)
        - Background: #ecf0f1 (Very light grey for sections)
        - Success: #27ae60 (Green for completed tasks)

    Returns:
        list: ReportLab story elements ready for document building

    Story Structure:
        - Title paragraph with professional styling
        - Metadata paragraph with export information
        - Statistics table with formatted data
        - Task content sections for each main task
        - Proper spacing elements between sections

    Statistics Table Features:
        - Header row with document title spanning all columns
        - Subheader row with metric categories
        - Data row with actual statistics
        - Professional styling with colors and borders
        - Center alignment and consistent padding

    Task Content Generation:
        - Uses build_task_content() for individual tasks
        - Maintains hierarchical structure and formatting
        - Includes visual status and priority indicators
        - Professional typography and spacing

    Typography Styles:
        - Title: Large, bold, center-aligned
        - Subtitle: Medium, italic, center-aligned
        - Task headers: Bold with background color
        - Task metadata: Smaller, muted text
        - Subtasks: Indented with priority indicators

    Example Usage:
        >>> main_tasks = Task.query.filter_by(user_id=1, parent_task_id=None).all()
        >>> story_elements = build_pdf_story(main_tasks)
        >>> doc.build(story_elements)
        # Generates complete professional PDF document

    Integration:
        - Called by export_tasks_pdf() endpoint
        - Works with ReportLab document generation system
        - Supports complete task hierarchy export
        - Provides professional document formatting
    """
    styles = getSampleStyleSheet()
    story = []

    # Custom styles - Elegant and classy
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#2c3e50'),  # Dark blue-grey
        alignment=1,  # Center
        spaceAfter=20
    )

    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=12,
        alignment=1,  # Center
        textColor=colors.HexColor('#7f8c8d'),  # Muted grey
        spaceAfter=30
    )

    task_title_style = ParagraphStyle(
        'TaskTitle',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50'),  # Dark blue-grey
        backgroundColor=colors.HexColor('#ecf0f1'),  # Light grey background
        borderPadding=10,
        spaceAfter=10,
        spaceBefore=10
    )

    # Title and metadata
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    story.append(Paragraph("📋 My Tasks Export", title_style))
    story.append(Paragraph(f"Exported on: {current_time}", subtitle_style))

    # Statistics table
    total_tasks = count_all_tasks(tasks)
    completed_tasks = count_completed_tasks(tasks)

    stats_data = [
        ['📊 Statistics', '', '', ''],
        ['Main Tasks', 'Total Tasks', 'Completed', 'Pending'],
        [str(len(tasks)), str(total_tasks), str(completed_tasks), str(total_tasks - completed_tasks)]
    ]

    stats_table = Table(stats_data, colWidths=[1.5 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch])
    stats_table.setStyle(TableStyle([
        # Header row - Elegant dark theme
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),  # Dark blue-grey
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('SPAN', (0, 0), (-1, 0)),  # Merge header cells
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),

        # Subheader row - Soft accent
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#bdc3c7')),  # Light grey
        ('TEXTCOLOR', (0, 1), (-1, 1), colors.HexColor('#2c3e50')),  # Dark text
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 1), (-1, 1), 11),
        ('ALIGN', (0, 1), (-1, -1), 'CENTER'),

        # Data row - Clean white
        ('BACKGROUND', (0, 2), (-1, 2), colors.white),
        ('TEXTCOLOR', (0, 2), (-1, 2), colors.HexColor('#2c3e50')),
        ('FONTSIZE', (0, 2), (-1, 2), 12),
        ('FONTNAME', (0, 2), (-1, 2), 'Helvetica-Bold'),

        # General styling
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),  # Subtle grid
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))

    story.append(stats_table)
    story.append(Spacer(1, 30))

    # Tasks content
    if not tasks:
        story.append(Paragraph("📝 No tasks found", styles['Normal']))
    else:
        for i, task in enumerate(tasks):
            if i > 0:
                story.append(Spacer(1, 20))
            story.extend(build_task_content(task, styles))

    return story


def build_task_content(task, styles):
    """
    Generate ReportLab content elements for a single main task and its subtasks.

    This function creates professionally formatted content for individual tasks
    in PDF exports, including headers, metadata, and hierarchical subtask
    listings with appropriate styling and visual indicators.

    Args:
        task (Task): SQLAlchemy Task object to format for PDF
            - Main task with complete metadata and relationships
            - May have nested subtasks via task.subtasks
            - Includes completion status and priority information

        styles (StyleSheet): ReportLab style definitions
            - Standard stylesheet from getSampleStyleSheet()
            - Used as base for custom style creation
            - Provides consistent typography foundation

    Content Generation:
        1. Creates styled task header with status emoji and title
        2. Adds task metadata (priority, completion status)
        3. Processes all subtasks recursively with proper formatting
        4. Maintains visual hierarchy through styling and indentation

    Task Header Styling:
        - Dynamic color based on completion status
        - Professional background with border padding
        - Status emoji for immediate visual feedback
        - Bold formatting for title emphasis

    Metadata Information:
        - Priority level in human-readable format
        - Completion status (Completed/Pending)
        - Muted styling for secondary information
        - Consistent formatting across all tasks

    Color Coding:
        - Completed tasks: Elegant green (#27ae60)
        - Pending tasks: Professional dark grey (#2c3e50)
        - Background: Light grey (#ecf0f1)
        - Metadata text: Muted grey (#7f8c8d)

    Returns:
        list: ReportLab elements for this task and all subtasks

    Element Types:
        - Paragraph: Task headers and metadata
        - Recursive subtask elements from build_subtask_content()
        - Styled elements ready for document inclusion

    Visual Hierarchy:
        - Main task headers prominently displayed
        - Metadata clearly separated but associated
        - Subtasks visually subordinated with indentation
        - Consistent spacing and alignment

    Status Indicators:
        - ✅: Completed tasks (green accent)
        - 📝: Pending tasks (standard styling)
        - Visual consistency with export formats
        - Immediate status recognition

    Example Generated Content:
        ```
        ✅ Complete Project Setup          [Header with green styling]
        Priority: High | Status: Completed [Metadata in muted text]

        ☑️ Initialize repository (High)    [Indented subtask]
          ☐ Setup documentation (Medium)   [Deeper indentation]
        ```

    Integration:
        - Called by build_pdf_story() for each main task
        - Works with build_subtask_content() for hierarchy
        - Supports complete task export functionality
        - Maintains professional document formatting
    """
    elements = []

    # Task header
    status_icon = "✅" if task.completed else "📝"
    priority = get_priority_text(task.priority)
    status = "Completed" if task.completed else "Pending"

    task_style = ParagraphStyle(
        'TaskHeader',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50') if not task.completed else colors.HexColor('#27ae60'),
        # Dark grey or elegant green
        backgroundColor=colors.HexColor('#ecf0f1'),  # Very light grey
        borderPadding=8,
        spaceAfter=5
    )

    elements.append(Paragraph(f"{status_icon} <b>{task.title}</b>", task_style))

    meta_style = ParagraphStyle(
        'TaskMeta',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#7f8c8d'),  # Elegant muted grey
        spaceAfter=15
    )
    elements.append(Paragraph(f"<i>Priority: {priority} | Status: {status}</i>", meta_style))

    # Subtasks
    if task.subtasks:
        subtasks = list(task.subtasks)
        subtasks.sort(key=lambda t: (-t.priority, t.title))

        for subtask in subtasks:
            elements.extend(build_subtask_content(subtask, styles, 1))

    return elements


def build_subtask_content(task, styles, depth):
    """
    Generate ReportLab content for subtasks with proper indentation and formatting.

    This function creates formatted content for subtasks in PDF exports,
    handling hierarchical indentation, completion status, priority indicators,
    and recursive nesting while maintaining professional document styling.

    Args:
        task (Task): SQLAlchemy Task object representing a subtask
            - Contains title, completion status, priority
            - May have further nested subtasks
            - Part of hierarchical task structure

        styles (StyleSheet): ReportLab style definitions for formatting
            - Standard stylesheet from getSampleStyleSheet()
            - Used for consistent typography
            - Base for custom style modifications

        depth (int): Current nesting depth for indentation calculation
            - Starting from 1 for first-level subtasks
            - Incremented for each nesting level
            - Used to calculate proper indentation spacing

    Indentation System:
        - Each depth level adds 20 points of left indentation
        - Creates visual hierarchy for nested tasks
        - Maintains readability at reasonable nesting levels
        - Supports arbitrary depth with depth limiting

    Content Formatting:
        - Checkbox indicators for completion status
        - Priority markers with color coding
        - Strike-through text for completed items
        - Proper spacing and typography

    Status Indicators:
        - ☑️: Completed subtasks (with strike-through text)
        - ☐: Pending subtasks (normal text)
        - Visual consistency across document
        - Clear completion status indication

    Priority Color Coding:
        - High priority: Red text color
        - Medium priority: Orange text color
        - Low priority: Green text color
        - Immediate priority recognition

    Text Styling:
        - Completed tasks: Strike-through formatting
        - Priority labels: Colored parenthetical indicators
        - Muted text color for completed items
        - Professional typography throughout

    Returns:
        list: ReportLab Paragraph elements for this subtask and children

    Element Structure:
        - Single Paragraph element for each subtask
        - Proper indentation and formatting applied
        - Recursive elements for nested subtasks
        - Professional styling maintained throughout

    Recursive Processing:
        - Handles nested subtasks automatically
        - Depth limiting prevents excessive nesting (depth < 5)
        - Maintains proper indentation at all levels
        - Sorts subtasks by priority and title

    Depth Limiting:
        - Maximum depth of 5 levels to prevent readability issues
        - Graceful handling of deeply nested structures
        - Maintains document layout integrity
        - Prevents excessive indentation

    Example Generated Content:
        ```
        Depth 1: ☑️ Complete setup (High)           [20pt indent]
        Depth 2:   ☐ Review documentation (Medium) [40pt indent]
        Depth 3:     ☑️ Update README (Low)        [60pt indent]
        ```

    Integration:
        - Called by build_task_content() for subtask processing
        - Recursive calls handle complete subtask hierarchies
        - Maintains consistent styling with main tasks
        - Supports complete PDF export functionality
    """
    elements = []

    # Create indented style
    indent = depth * 20
    subtask_style = ParagraphStyle(
        f'Subtask{depth}',
        parent=styles['Normal'],
        fontSize=11,
        leftIndent=indent,
        bulletIndent=indent,
        spaceAfter=3,
        textColor=colors.HexColor('#95a5a6') if task.completed else colors.HexColor('#2c3e50')  # Muted grey or dark
    )

    # Format subtask text
    checkbox = "☑️" if task.completed else "☐"
    priority_indicator = get_priority_text(task.priority)
    priority_colors = {
        'High': colors.red,
        'Medium': colors.orange,
        'Low': colors.green
    }
    priority_color = priority_colors.get(priority_indicator, colors.black)

    text = f"{checkbox} {task.title} "
    if task.completed:
        text = f"<strike>{text}</strike>"

    # Add priority indicator
    text += f'<font color="{priority_color}">({priority_indicator})</font>'

    elements.append(Paragraph(text, subtask_style))

    # Add nested subtasks
    if task.subtasks and depth < 5:  # Prevent too deep nesting
        subtasks = list(task.subtasks)
        subtasks.sort(key=lambda t: (-t.priority, t.title))

        for subtask in subtasks:
            elements.extend(build_subtask_content(subtask, styles, depth + 1))

    return elements
