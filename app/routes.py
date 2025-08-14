from flask import Blueprint, render_template, redirect, url_for, request, session, jsonify, flash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models import User, Task
import json
from flask import make_response
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import io

# Define a Flask Blueprint for the main routes of the application
main = Blueprint('main', __name__)

# Maximum depth allowed for nested subtasks
MAX_NESTING_DEPTH = 5


@main.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user login.

    GET: Render the login page.
    POST: Authenticate the user and log them in if credentials are valid.

    Returns:
        - On GET: Rendered login page.
        - On POST: Redirect to the index page if login is successful, otherwise re-render login page with an error message.
    """
    error_message = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            session.permanent = True
            return redirect(url_for('main.index'))
        else:
            error_message = 'Login Unsuccessful. Please check username and password'
    return render_template('login.html', error_message=error_message)


@main.route('/logout')
@login_required
def logout():
    """
    Log out the currently logged-in user.

    Returns:
        Redirect to the login page.
    """
    logout_user()
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle user registration.

    GET: Render the registration page.
    POST: Create a new user account with the provided details.

    Returns:
        - On GET: Rendered registration page.
        - On POST: Redirect to the login page after successful registration.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        security_question = request.form.get('security_question')
        security_answer = request.form.get('security_answer')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password, security_question=security_question,
                        security_answer=security_answer)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('main.login'))
    return render_template('register.html')


@main.route('/')
@login_required
def index():
    """
    Display the main task management page.

    Retrieves tasks for the current user, applies sorting and filtering, and renders the index page.

    Query Parameters:
        - sort_by: Field to sort tasks by (default: 'priority').
        - filter_by: Filter tasks by priority (optional).

    Returns:
        Rendered index page with tasks and suggested tasks.
    """
    sort_by = request.args.get('sort_by', 'priority')
    filter_by = request.args.get('filter_by', '')

    # Only get main tasks (not subtasks) for the main view
    if filter_by:
        tasks = Task.query.filter_by(user_id=current_user.id, priority=filter_by, parent_task_id=None).all()
    else:
        tasks = Task.query.filter_by(user_id=current_user.id, parent_task_id=None).all()

    if sort_by == 'priority':
        tasks.sort(key=lambda task: task.priority, reverse=True)
    else:
        tasks.sort(key=lambda task: getattr(task, sort_by))

    # Load subtasks for each task to avoid N+1 queries
    for task in tasks:
        # Force loading of subtasks relationship
        task.subtasks.all()

    suggested_tasks = [
        "Buy groceries",
        "Read a book",
        "Exercise",
        "Clean the house",
        "Write a blog post",
        "Learn a new skill",
        "Call a friend",
        "Plan a trip",
        "Cook a new recipe",
        "Organize your workspace"
    ]
    return render_template('index.html', tasks=tasks, suggested_tasks=suggested_tasks, sort_by=sort_by,
                           filter_by=filter_by, max_depth=MAX_NESTING_DEPTH)


@main.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    """
    Add a new task or subtask.

    GET: Render the task addition form.
    POST: Process the form data to create a new task or subtask.

    Form Data:
        - title (str): The title of the task (required).
        - priority (int): The priority of the task (default: 1).
        - parent_task_id (int, optional): The ID of the parent task for subtasks.

    Returns:
        - On success: Redirect to the index page or parent task details page.
        - On failure: Redirect to the index page with an error message.
    """
    # Debug: Print all form data

    title = request.form.get('title')
    priority = int(request.form.get('priority', 1))
    parent_task_id = request.form.get('parent_task_id')

    if not title:
        flash('Task title is required!', 'error')
        return redirect(url_for('main.index'))

    # Convert parent_task_id to int if it exists and is not empty
    if parent_task_id and parent_task_id.strip():
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

        if parent_task and parent_task.user_id == current_user.id:
            print(f"Parent task belongs to current user")
            # Check if we can add subtask (depth limit)
            if not parent_task.can_add_subtask(MAX_NESTING_DEPTH):
                flash(f'Maximum nesting depth of {MAX_NESTING_DEPTH} levels reached!', 'error')
                return redirect(url_for('main.task_details', task_id=parent_task_id))
            depth = parent_task.depth + 1
        else:
            flash('Invalid parent task or access denied!', 'error')
            return redirect(url_for('main.index'))

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

    # Redirect logic
    if parent_task_id:
        flash('Subtask added successfully!', 'success')
        return redirect(url_for('main.task_details', task_id=parent_task_id))
    else:
        flash('Task added successfully!', 'success')
        return redirect(url_for('main.index'))


@main.route('/complete/<int:task_id>')
@login_required
def complete(task_id):
    """
    Toggle the completion status of a task and its subtasks.

    Args:
        task_id (int): The ID of the task to toggle.

    Returns:
        - Redirect to the parent task details page if the task is a subtask.
        - Redirect to the index page otherwise.
    """
    def toggle_subtasks(task, completed_status):
        """Recursively mark all subtasks as completed or not completed."""
        for subtask in task.subtasks:
            subtask.completed = completed_status
            toggle_subtasks(subtask, completed_status)

    task = db.session.get(Task, task_id)
    if task and task.user_id == current_user.id:
        task.completed = not task.completed
        toggle_subtasks(task, task.completed)  # Update all subtasks
        db.session.commit()

        # If it's a subtask, redirect to the appropriate parent task details
        if task.parent_task_id:
            # Check if we're viewing a nested subtask - redirect to root task
            root_task = task.root_task
            return redirect(url_for('main.task_details', task_id=root_task.id))

    return redirect(url_for('main.index'))


@main.route('/delete/<int:task_id>')
@login_required
def delete(task_id):
    """
    Delete a task and its subtasks.

    Args:
        task_id (int): The ID of the task to delete.

    Returns:
        - Redirect to the parent task details page if the task is a subtask.
        - Redirect to the index page otherwise.
    """
    task = db.session.get(Task, task_id)
    if task and task.user_id == current_user.id:
        # Store parent task ID and root task ID before deletion
        parent_id = task.parent_task_id
        root_task_id = task.root_task.id if task.parent_task_id else None

        # Delete the task (cascade will handle all subtasks)
        db.session.delete(task)
        db.session.commit()

        # If it was a subtask, redirect to root task details
        if parent_id:
            return redirect(url_for('main.task_details', task_id=root_task_id))

    return redirect(url_for('main.index'))

@main.route('/task/<int:task_id>')
@login_required
def task_details(task_id):
    """
    Display the details of a specific task, including its subtasks and breadcrumb navigation.

    Args:
        task_id (int): The ID of the task to display.

    Returns:
        Rendered task details page with the task, its subtasks, and breadcrumb navigation.
    """
    task = Task.query.get_or_404(task_id)

    # Ensure the task belongs to the current user
    if task.user_id != current_user.id:
        return redirect(url_for('main.index'))

    # Get all subtasks with their subtasks loaded
    def load_subtasks_recursive(parent_task):
        """
        Recursively load all subtasks for a given parent task.

        Args:
            parent_task (Task): The parent task whose subtasks need to be loaded.

        Returns:
            list: A list of all subtasks for the parent task.
        """
        subtasks = parent_task.subtasks.all()
        for subtask in subtasks:
            load_subtasks_recursive(subtask)
        return subtasks

    subtasks = load_subtasks_recursive(task)

    # Get breadcrumb navigation for nested tasks
    breadcrumbs = []
    if task.parent_task_id:
        breadcrumbs = task.get_ancestors()
        breadcrumbs.append(task)

    return render_template('task_details.html', task=task, subtasks=subtasks,
                           breadcrumbs=breadcrumbs, max_depth=MAX_NESTING_DEPTH)


@main.route('/check_username', methods=['POST'])
def check_username():
    """
    Check if a username already exists in the database.

    Returns:
        JSON response indicating whether the username exists.
    """
    existing_usernames = [user.username for user in User.query.all()]
    username = request.form.get('username')
    if username in existing_usernames:
        return jsonify({'exists': True})
    return jsonify({'exists': False})


@main.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Handle the forgot password process.

    GET: Render the forgot password page.
    POST: Verify the username and redirect to the security answer page if valid.

    Returns:
        - On GET: Rendered forgot password page.
        - On POST: JSON response or redirect to the security answer page.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            session['username'] = username
            session['security_question'] = user.security_question
            return redirect(url_for('main.security_answer'))
        else:
            return jsonify({'message': 'Username not found.', 'status': 'danger'})
    return render_template('forgot_password.html')


@main.route('/security_answer', methods=['GET', 'POST'])
def security_answer():
    """
    Handle the security question verification process.

    GET: Render the security answer page.
    POST: Verify the security answer and redirect to the password reset page if valid.

    Returns:
        - On GET: Rendered security answer page.
        - On POST: JSON response indicating success or failure.
    """
    username = session.get('username')
    security_question = session.get('security_question')
    if request.method == 'POST':
        security_answer = request.form.get('security_answer')
        user = User.query.filter_by(username=username).first()
        if user and user.security_answer == security_answer:
            return redirect(url_for('main.reset_password'))
        else:
            return jsonify({'status': 'danger', 'message': 'Incorrect security answer.'})
    return render_template('security_answer.html', security_question=security_question)


@main.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """
    Handle the password reset process.

    GET: Render the password reset page.
    POST: Update the user's password in the database.

    Returns:
        - On GET: Rendered password reset page.
        - On POST: JSON response indicating success or failure.
    """
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        username = session.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            user.password = hashed_password
            db.session.commit()
            return jsonify({'message': 'Your password has been reset successfully.', 'status': 'success'})
    return render_template('reset_password.html')


@main.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit(task_id):
    """
    Edit the details of a specific task.

    Args:
        task_id (int): The ID of the task to edit.

    Returns:
        - On GET: Rendered edit task page.
        - On POST: Redirect to the appropriate page after updating the task.
    """
    task = Task.query.get(task_id)
    if not task or task.user_id != current_user.id:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        task.title = request.form.get('title')
        task.priority = request.form.get('priority')
        db.session.commit()

        # If it's a subtask, redirect to root task details
        if task.parent_task_id:
            root_task = task.root_task
            return redirect(url_for('main.task_details', task_id=root_task.id))

        return redirect(url_for('main.index'))
    return render_template('edit_task.html', task=task)


@main.route('/add_suggested/<string:task_title>', methods=['POST'])
@login_required
def add_suggested(task_title):
    """
    Add a suggested task to the user's task list.

    Args:
        task_title (str): The title of the suggested task.

    Returns:
        Redirect to the index page after adding the task.
    """
    priority = request.form.get('priority', 1)
    new_task = Task(title=task_title, user_id=current_user.id, priority=priority, depth=0)
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('main.index'))

@main.route('/import_markdown', methods=['POST'])
def import_markdown():
    """
    Handle the import of tasks from a markdown file or parsed data.

    This function supports two modes of importing:
    1. Importing from parsed tasks data provided in the request form.
    2. Uploading a markdown file directly and parsing its content.

    Request Form:
        - parsed_tasks (str, optional): JSON string of parsed tasks data.
        - markdown_file (File, optional): Uploaded markdown file.
        - default_priority (int, optional): Default priority for tasks (default: 2).

    Returns:
        Redirect to the index page with a success or error message.
    """
    try:
        # Check if parsed tasks data is provided (from preview)
        if 'parsed_tasks' in request.form:
            # Import from preview data
            parsed_tasks = json.loads(request.form.get('parsed_tasks'))
            default_priority = int(request.form.get('default_priority', 2))

            imported_count = import_tasks_from_data(parsed_tasks, default_priority)
            flash(f'Successfully imported {imported_count} tasks!', 'success')

        else:
            # Direct file upload without preview
            if 'markdown_file' not in request.files:
                flash('No file selected', 'error')
                return redirect(url_for('main.index'))

            file = request.files['markdown_file']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(url_for('main.index'))

            if file and allowed_file(file.filename):
                # Read file content
                content = file.read().decode('utf-8')
                default_priority = int(request.form.get('default_priority', 2))

                # Parse markdown content
                parsed_tasks = parse_markdown_content(content)

                if not parsed_tasks:
                    flash('No tasks found in the markdown file', 'warning')
                    return redirect(url_for('main.index'))

                imported_count = import_tasks_from_data(parsed_tasks, default_priority)
                flash(f'Successfully imported {imported_count} tasks from markdown file!', 'success')
            else:
                flash('Invalid file type. Please upload a .md or .txt file', 'error')

    except Exception as e:
        flash(f'Error importing markdown file: {str(e)}', 'error')

    return redirect(url_for('main.index'))


def allowed_file(filename):
    """
    Check if the uploaded file has an allowed extension.

    Args:
        filename (str): The name of the uploaded file.

    Returns:
        bool: True if the file has an allowed extension, False otherwise.
    """
    ALLOWED_EXTENSIONS = {'md', 'txt'}
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def parse_markdown_content(content):
    """
    Parse markdown content and extract tasks with a nested structure.

    Args:
        content (str): The content of the markdown file.

    Returns:
        list: A list of tasks with their nested subtasks.
    """
    lines = content.split('\n')
    tasks = []
    task_stack = []  # Stack to track nested structure

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Count indentation level for nested structure
        original_line = line
        indent_level = 0
        while line.startswith('  ') or line.startswith('\t'):
            indent_level += 1
            line = line[2:] if line.startswith('  ') else line[1:]

        # Main task (# Header)
        if line.startswith('# '):
            title = line[2:].strip()
            new_task = {
                'title': title,
                'completed': False,
                'subtasks': [],
                'depth': 0
            }
            tasks.append(new_task)
            task_stack = [new_task]  # Reset stack with new main task

        # Subtask headers (##, ###, etc.)
        elif line.startswith('#'):
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

            if task_stack:
                task_stack[-1]['subtasks'].append(new_task)
                task_stack.append(new_task)
            else:
                tasks.append(new_task)
                task_stack = [new_task]

        # Checkbox tasks (- [ ] or - [x])
        elif line.startswith('- [') and (line[3] in ['x', ' ', 'X']):
            completed = line[3].lower() == 'x'
            title = line[5:].strip()

            new_task = {
                'title': title,
                'completed': completed,
                'subtasks': [],
                'depth': indent_level
            }

            # Find appropriate parent based on indentation
            while len(task_stack) > indent_level + 1:
                task_stack.pop()

            if task_stack and indent_level > 0:
                task_stack[-1]['subtasks'].append(new_task)
                task_stack.append(new_task)
            else:
                tasks.append(new_task)
                task_stack = [new_task]

        # Bullet points (- or *)
        elif line.startswith('- ') or line.startswith('* '):
            title = line[2:].strip()

            new_task = {
                'title': title,
                'completed': False,
                'subtasks': [],
                'depth': indent_level
            }

            # Find appropriate parent based on indentation
            while len(task_stack) > indent_level + 1:
                task_stack.pop()

            if task_stack and indent_level > 0:
                task_stack[-1]['subtasks'].append(new_task)
                task_stack.append(new_task)
            else:
                tasks.append(new_task)
                task_stack = [new_task]

    return tasks


def import_tasks_from_data(parsed_tasks, default_priority):
    """
    Import tasks from parsed data into the database with a nested structure.

    Args:
        parsed_tasks (list): A list of parsed tasks with nested subtasks.
        default_priority (int): The default priority to assign to tasks.

    Returns:
        int: The total number of tasks imported.
    """
    imported_count = 0

    def create_task_recursive(task_data, parent_id=None, current_depth=0):
        """
        Recursively create tasks and their subtasks in the database.

        Args:
            task_data (dict): The data for the task to create.
            parent_id (int, optional): The ID of the parent task.
            current_depth (int): The current depth of the task in the hierarchy.

        Returns:
            Task: The created task object.
        """
        nonlocal imported_count

        # Prevent excessive nesting
        if current_depth >= MAX_NESTING_DEPTH:
            return None

        # Create task
        task = Task(
            title=task_data['title'],
            completed=task_data['completed'],
            priority=default_priority,
            parent_task_id=parent_id,
            user_id=current_user.id,
            depth=current_depth
        )
        db.session.add(task)
        db.session.flush()  # Get the ID without committing
        imported_count += 1

        # Create subtasks recursively
        for subtask_data in task_data.get('subtasks', []):
            create_task_recursive(subtask_data, task.id, current_depth + 1)

        return task

    for task_data in parsed_tasks:
        create_task_recursive(task_data)

    db.session.commit()
    return imported_count

@main.route('/export_tasks')
@login_required
def export_tasks():
    """
    Export all user tasks to a markdown file.

    Retrieves all main tasks for the current user, sorts them by priority and title,
    generates markdown content, and prepares it for download as a file.

    Returns:
        Response: A Flask response object containing the markdown file for download.
    """
    try:
        # Get all main tasks (no parent) for the current user
        main_tasks = Task.query.filter_by(user_id=current_user.id, parent_task_id=None).all()

        # Sort tasks by priority (high to low) then by title
        main_tasks.sort(key=lambda t: (-t.priority, t.title))

        # Generate markdown content
        markdown_content = generate_markdown_export(main_tasks)

        # Create response with markdown content
        response = make_response(markdown_content)

        # Set headers for file download
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"my_tasks_{timestamp}.md"

        response.headers['Content-Type'] = 'text/markdown'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

        return response

    except Exception as e:
        flash(f'Error exporting tasks: {str(e)}', 'error')
        return redirect(url_for('main.index'))

def get_priority_text(priority):
    """Convert priority number to text"""
    priority_map = {
        1: "Low",
        2: "Medium",
        3: "High"
    }
    return priority_map.get(priority, "Medium")

def generate_markdown_export(tasks):
    """
    Generate markdown content from a list of tasks.

    Args:
        tasks (list): A list of main tasks to be exported.

    Returns:
        str: A string containing the markdown representation of the tasks.
    """
    content = []

    # Add header with metadata
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content.append(f"# My Tasks Export")
    content.append(f"**Exported on:** {current_time}")
    content.append(f"**Total main tasks:** {len(tasks)}")
    content.append("")

    # Add summary statistics
    total_tasks = count_all_tasks(tasks)
    completed_tasks = count_completed_tasks(tasks)
    content.append(f"**Total tasks (including subtasks):** {total_tasks}")
    content.append(f"**Completed tasks:** {completed_tasks}")
    content.append(f"**Pending tasks:** {total_tasks - completed_tasks}")
    content.append("")
    content.append("---")
    content.append("")

    # Process each main task
    for task in tasks:
        content.extend(format_task_as_markdown(task, is_main_task=True))
        content.append("")  # Add spacing between main tasks

    return '\n'.join(content)


def format_task_as_markdown(task, is_main_task=False, depth=0):
    """
    Format a single task and its subtasks as markdown.

    Args:
        task (Task): The task to format.
        is_main_task (bool): Whether the task is a main task.
        depth (int): The depth of the task in the hierarchy for indentation.

    Returns:
        list: A list of strings representing the task in markdown format.
    """
    lines = []

    if is_main_task:
        # Main task as a header
        status_icon = "✅" if task.completed else "📝"
        priority_text = get_priority_text(task.priority)
        lines.append(f"## {status_icon} {task.title}")
        lines.append(f"**Priority:** {priority_text}")
        lines.append(f"**Status:** {'Completed' if task.completed else 'Pending'}")
        lines.append("")
    else:
        # Subtask as checkbox with proper indentation
        indent = "  " * depth
        checkbox = "[x]" if task.completed else "[ ]"
        priority_indicator = get_priority_indicator(task.priority)
        lines.append(f"{indent}- {checkbox} {task.title} {priority_indicator}")

    # Add subtasks recursively
    if task.subtasks:
        subtasks = list(task.subtasks)
        subtasks.sort(key=lambda t: (-t.priority, t.title))

        for subtask in subtasks:
            if is_main_task:
                lines.extend(format_task_as_markdown(subtask, False, 0))
            else:
                lines.extend(format_task_as_markdown(subtask, False, depth + 1))

    return lines


def get_priority_text(priority):
    """
    Convert a priority number to descriptive text.

    Args:
        priority (int): The priority level of the task.

    Returns:
        str: A string representing the priority level.
    """
    priority_map = {
        1: "Low",
        2: "Medium",
        3: "High"
    }
    return priority_map.get(priority, "Medium")


def get_priority_indicator(priority):
    """
    Get a visual indicator for the task's priority.

    Args:
        priority (int): The priority level of the task.

    Returns:
        str: A string containing an emoji representing the priority level.
    """
    priority_map = {
        1: "🔵",  # Low priority
        2: "🟡",  # Medium priority
        3: "🔴"  # High priority
    }
    return priority_map.get(priority, "🟡")


def count_all_tasks(tasks):
    """
    Count the total number of tasks, including all subtasks.

    Args:
        tasks (list): A list of tasks to count.

    Returns:
        int: The total number of tasks.
    """
    count = 0
    for task in tasks:
        count += 1  # Count the task itself
        if task.subtasks:
            count += count_all_tasks(list(task.subtasks))
    return count


def count_completed_tasks(tasks):
    """
    Count the total number of completed tasks, including subtasks.

    Args:
        tasks (list): A list of tasks to count.

    Returns:
        int: The total number of completed tasks.
    """
    count = 0
    for task in tasks:
        if task.completed:
            count += 1
        if task.subtasks:
            count += count_completed_tasks(list(task.subtasks))
    return count


@main.route('/export_tasks_pdf')
@login_required
def export_tasks_pdf():
    """Export tasks to PDF format using ReportLab - One click download"""
    try:
        # Get all main tasks for the current user
        main_tasks = Task.query.filter_by(user_id=current_user.id, parent_task_id=None).all()
        main_tasks.sort(key=lambda t: (-t.priority, t.title))

        # Create PDF buffer
        buffer = io.BytesIO()

        # Create PDF document
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"my_tasks_{timestamp}.pdf"

        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )

        # Build PDF content
        story = build_pdf_story(main_tasks)

        # Generate PDF
        doc.build(story)
        buffer.seek(0)

        # Create response for download
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

        return response

    except ImportError:
        flash('PDF export requires ReportLab. Please install it: pip install reportlab', 'error')
        return redirect(url_for('main.export_tasks'))  # Fallback to markdown
    except Exception as e:
        flash(f'Error exporting to PDF: {str(e)}', 'error')
        return redirect(url_for('main.index'))


def build_pdf_story(tasks):
    """Build the PDF content using ReportLab"""
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
    """Build content for a single main task"""
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
    """Build content for subtasks with proper indentation"""
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

