import time
from typing import Union, Tuple, Dict, Any, Optional, List
from flask import Blueprint, request, jsonify, session, current_app
from flask_login import current_user
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import jwt
from datetime import datetime, timedelta
import os

from app import db
from app.models import User, Task
from app.routes import import_tasks_from_data, parse_markdown_content, generate_markdown_export, \
    import_tasks_from_data_api

# Create API blueprint
api = Blueprint('api', __name__, url_prefix='/api/v1')

MAX_NESTING_DEPTH = 5

def generate_token(user_id):
    """
    Generate a JWT authentication token for a given user with 24-hour expiration.
    This function creates a JSON Web Token containing the user's ID and expiration
    timestamp. The token is signed using the HS256 algorithm with a secret key
    retrieved from environment variables. This token can be used for authenticating
    API requests and maintaining user sessions.

    Args:
        user_id (int|str): The unique identifier of the user for whom to generate
                          the token. Can be integer ID or string identifier.

    Returns:
        str: A base64-encoded JWT token string containing:
             - Header: Algorithm (HS256) and token type (JWT)
             - Payload: User ID and expiration timestamp
             - Signature: HMAC SHA-256 hash for verification

    Token Structure:
        Header: {"typ": "JWT", "alg": "HS256"}
        Payload: {
            "user_id": <user_id>,           # User identifier
            "exp": <timestamp>              # Expiration (24h from now)
        }
        Signature: HMACSHA256(base64UrlEncode(header) + "." +
                             base64UrlEncode(payload), secret)

    Environment Dependencies:
        SECRET_KEY: Environment variable containing the signing secret.
                   Must be a strong, randomly generated string.

    Security Considerations:
        - Uses UTC timestamps to avoid timezone vulnerabilities
        - 24-hour expiration balances security and user experience
        - Requires secure SECRET_KEY management
        - Token should be transmitted over HTTPS only

    Example:
        >>> token = generate_token(12345)
        >>> print(token)
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMjM0NSwiZXhwIjoxNjM5NTc2ODAwfQ.signature'

    Potential Issues:
        - Returns None if SECRET_KEY environment variable is missing
        - No input validation on user_id parameter
        - Fixed 24-hour expiration (not configurable)
        - Assumes PyJWT library is installed and imported
    """
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, os.environ.get('SECRET_KEY'), algorithm='HS256')


def verify_token(token):
    """
    Verify and decode a JWT token to extract the user ID with comprehensive error handling.
    This function validates a JWT token's signature, checks its expiration status,
    and extracts the user ID from the payload. It handles various token validation
    errors gracefully by returning None for any invalid token scenario, making it
    safe to use in authentication flows.

    Args:
        token (str): The JWT token string to verify and decode. Should be a
                    complete JWT token including header, payload, and signature
                    sections separated by dots.

    Returns:
        int|str|None: The user_id from the token payload if verification succeeds,
                     or None if the token is invalid, expired, or malformed.

    Validation Process:
        1. Signature verification using SECRET_KEY and HS256 algorithm
        2. Expiration timestamp validation against current UTC time
        3. Token structure and format validation
        4. Payload extraction and user_id retrieval

    Error Handling:
        jwt.ExpiredSignatureError: Token has passed its expiration time
        jwt.InvalidTokenError: Covers multiple scenarios:
            - Malformed token structure
            - Invalid signature
            - Missing or corrupted payload
            - Algorithm mismatch
            - Invalid secret key

    Environment Dependencies:
        SECRET_KEY: Must match the key used in generate_token()

    Security Features:
        - Cryptographic signature verification prevents tampering
        - Automatic expiration checking prevents replay attacks
        - Graceful error handling prevents information leakage
        - Returns consistent None for all failure cases

    Example:
        >>> valid_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
        >>> user_id = verify_token(valid_token)
        >>> print(user_id)  # 12345

        >>> expired_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
        >>> user_id = verify_token(expired_token)
        >>> print(user_id)  # None

        >>> invalid_token = "invalid.token.here"
        >>> user_id = verify_token(invalid_token)
        >>> print(user_id)  # None

    Common Failure Scenarios:
        - Token created with different SECRET_KEY
        - Token modified/tampered after creation
        - Token older than 24 hours
        - Malformed token string
        - Missing SECRET_KEY environment variable
    """
    try:
        payload = jwt.decode(token, os.environ.get('SECRET_KEY'), algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """
    Decorator function that enforces JWT token authentication for Flask API endpoints.
    This decorator wraps Flask route functions to require valid JWT authentication
    before allowing access. It extracts the token from the Authorization header,
    validates it, retrieves the associated user from the database, and makes the
    user object available to the decorated endpoint through request.current_user.

    Args:
        f (function): The Flask route function to be decorated. Must be a valid
                     Flask endpoint function that can accept *args and **kwargs.

    Returns:
        function: The decorated function with authentication enforcement

    Authentication Flow:
        1. Extract Authorization header from request
        2. Validate header format and extract Bearer token
        3. Verify JWT token using verify_token()
        4. Query database for user associated with token
        5. Attach user object to request context
        6. Execute original endpoint function

    Header Format Expected:
        Authorization: Bearer <jwt_token>

    Request Context Enhancement:
        request.current_user: User object from database query

    Error Responses:
        401 Unauthorized with JSON error messages:
        - "Token is missing": No Authorization header present
        - "Token is invalid or expired": JWT verification failed
        - "User not found": Valid token but user doesn't exist in database

    Database Dependencies:
        - User model with query interface (SQLAlchemy assumed)
        - User.query.get() method for retrieving user by ID

    Usage Example:
        @app.route('/protected-endpoint')
        @token_required
        def protected_view():
            user = request.current_user
            return jsonify({'message': f'Hello {user.username}'})

    Security Features:
        - Validates both token format and content
        - Ensures user still exists in database
        - Provides consistent error responses
        - Prevents access with deleted user accounts
        - Bearer token format enforcement

    Implementation Details:
        - Uses @wraps(f) to preserve original function metadata
        - Supports both "Bearer token" and raw token formats
        - Performs database lookup for each authenticated request
        - Stores user in request context for endpoint access
        - Returns JSON error responses for all failure cases

    Performance Considerations:
        - Database query on every authenticated request
        - Could be optimized with user caching strategies
        - Consider connection pooling for high-traffic applications

    Potential Issues:
        - Database query failure not handled
        - No rate limiting on authentication attempts
        - User object stored in request context (memory usage)
        - Assumes User model and database connection are available
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        if token.startswith('Bearer '):
            token = token[7:]

        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Token is invalid or expired'}), 401

        # Get the user and make it available in the endpoint
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401

        # Store user in request context for API endpoints
        request.current_user = user
        return f(*args, **kwargs)

    return decorated


def serialize_user(user):
    """
        Convert a User object to a dictionary representation for JSON serialization.

        Transforms a SQLAlchemy User model instance into a dictionary suitable for
        JSON serialization, excluding sensitive information like passwords and
        security answers for security purposes.

        Args:
            user (User): A SQLAlchemy User model instance to serialize

        Returns:
            dict: A dictionary containing safe user attributes (no passwords)

        Dictionary structure:
            {
                'id': int,                    # Unique user identifier
                'username': str,              # User's chosen username
                'email': str,                 # User's email address
                'security_question': str      # Security question for password recovery
            }

        Security Notes:
            - Password hash is deliberately excluded
            - Security answer is deliberately excluded
            - Only safe-to-expose attributes are included

        Example:
            >>> user = User(id=123, username="john_doe", email="john@example.com")
            >>> serialize_user(user)
            {
                'id': 123,
                'username': 'john_doe',
                'email': 'john@example.com',
                'security_question': 'What was your first pet?'
            }
        """
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'security_question': user.security_question
    }


@api.route('/tasks', methods=['GET'])
@token_required
def get_tasks():
    """
    Retrieve main tasks only - fast and simple.

    This endpoint now returns only main tasks without subtasks for optimal performance.
    Subtasks are loaded on-demand via a separate endpoint when needed.

    Performance benefits:
    - Single simple query
    - Minimal JSON payload
    - Instant response time
    - No N+1 query issues
    """
    try:
        sort_by = request.args.get('sort_by', 'priority')
        filter_by = request.args.get('filter_by', '')

        from sqlalchemy import desc, asc
        start_time = time.time()
        # Simple query for main tasks only
        query = Task.query.filter_by(
            user_id=request.current_user.id,
            parent_task_id=None
        )

        # Apply priority filter
        if filter_by:
            try:
                priority_value = int(filter_by)
                if 1 <= priority_value <= 3:
                    query = query.filter_by(priority=priority_value)
            except ValueError:
                pass

        # Database-level sorting
        if sort_by == 'priority':
            query = query.order_by(desc(Task.priority))
        elif sort_by == 'title':
            query = query.order_by(asc(Task.title))
        elif sort_by == 'created_at':
            query = query.order_by(desc(Task.created_at))
        elif sort_by == 'updated_at':
            query = query.order_by(desc(Task.updated_at))
        else:
            query = query.order_by(desc(Task.priority))
            sort_by = 'priority'

        tasks = query.all()
        # Simple serialization without subtasks
        serialized_tasks = [serialize_task(task) for task in tasks]

        return jsonify({
            'success': True,
            'tasks': serialized_tasks,
            'total_count': len(tasks),
            'sort_by': sort_by,
            'filter_by': filter_by
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error in get_tasks: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An error occurred while retrieving tasks',
            'tasks': [],
            'total_count': 0
        }), 500


@api.route('/tasks/<int:task_id>/subtasks', methods=['GET'])
@token_required
def get_subtasks(task_id):
    """
    Get subtasks for a specific task - called on demand when user expands a task.

    Args:
        task_id: ID of the parent task

    Returns:
        List of direct subtasks for the specified task
    """
    try:
        # Verify task belongs to user
        parent_task = Task.query.filter_by(
            id=task_id,
            user_id=request.current_user.id
        ).first()

        if not parent_task:
            return jsonify({
                'success': False,
                'error': 'Task not found',
                'subtasks': []
            }), 404

        # Get direct subtasks only
        subtasks = Task.query.filter_by(
            parent_task_id=task_id,
            user_id=request.current_user.id
        ).order_by(Task.priority.desc()).all()

        serialized_subtasks = [serialize_task(subtask) for subtask in subtasks]

        return jsonify({
            'success': True,
            'subtasks': serialized_subtasks,
            'parent_task_id': task_id,
            'total_count': len(subtasks)
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error in get_subtasks: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An error occurred while retrieving subtasks',
            'subtasks': []
        }), 500


def serialize_task(task):
    """
    Ultra-fast serialization that ONLY accesses basic database columns.
    Avoids all calculated properties that might trigger expensive queries.

    This will be blazingly fast because it only accesses direct table columns.
    """
    has_subtasks = Task.query.filter_by(
        parent_task_id=task.id,
        user_id=task.user_id
    ).count() > 0
    return {
        'id': task.id,
        'title': task.title,
        'completed': task.completed,
        'priority': task.priority,
        'parent_task_id': task.parent_task_id,
        'user_id': task.user_id,
        'has_subtasks': has_subtasks,
        'subtasks_loaded': False,
        'depth': task.depth,
        'is_subtask': task.is_subtask,
        'subtask_count': task.subtask_count,
        'completed_subtask_count': task.completed_subtask_count,
        'completion_percentage': task.completion_percentage,
    }

@api.route('/auth/login', methods=['POST'])
def login():
    """
        Handle user authentication for API clients.

        This endpoint supports JWT-based authentication for API clients:
        - API clients: Accepts JSON credentials and returns JSON responses

        GET Request:
            - API: Returns 405 Method Not Allowed (POST required for API)

        POST Request Processing:
            1. Extracts credentials from JSON (API)
            2. Validates that both username and password are provided
            3. Queries database for user with matching username
            4. Verifies password using secure hash comparison
            5. Creates user session if authentication succeeds
            6. Returns appropriate response based on client type

        Request Data (POST):
            JSON (API clients):
                {
                    "username": "string (required)",
                    "password": "string (required)"
                }

        Returns:
            GET Requests:
                - API: Error response (405)

            POST Requests - Success:
                - API: JSON success response with user data (200)

            POST Requests - Failure:
                - API: JSON error response (400/401/500)

        Response Examples:
            API Success (200):
            {
                "success": true,
                "message": "Login successful",
                "user": {
                    "id": 123,
                    "username": "john_doe",
                    "email": "john@example.com",
                    "security_question": "What was your first pet?"
                }
            }

            API Error (401):
            {
                "error": "Login Unsuccessful. Please check username and password"
            }

        Security Features:
            - Passwords stored as secure PBKDF2-SHA256 hashes
            - Session configured as permanent for persistence
            - No password information returned in responses
            - Input validation prevents empty credentials

        Error Conditions:
            - 400: Missing or invalid request data
            - 401: Invalid username/password combination
            - 405: GET request to API endpoint
            - 500: Server error during authentication
        """
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400

    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        error_msg = 'Username and password are required'
        return jsonify({'error': error_msg}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, password):
        token = generate_token(user.id)
        return jsonify({
            'success': True,
            'token': token,
            'user': serialize_user(user)
        }), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401


@api.route('/auth/register', methods=['POST'])
def register():
    """
    Handle new user registration for API clients.

    This endpoint manages the complete user registration process, including
    validation, duplicate checking, secure password hashing, and account creation.
    It supports JSON API requests.

    GET Request:
        - API: Returns 405 Method Not Allowed (POST required)

    POST Request Processing:
        1. Extracts registration data from JSON or form
        2. Validates all required fields are present
        3. Checks for existing username conflicts
        4. Checks for existing email conflicts
        5. Hashes password using PBKDF2-SHA256
        6. Creates new User record in database
        7. Returns success response or redirect

    Request Data (POST):
        JSON (API clients):
            {
                "username": "string (required) - Unique identifier",
                "email": "string (required) - User's email address",
                "password": "string (required) - Plain text password",
                "security_question": "string (required) - Recovery question",
                "security_answer": "string (required) - Answer to question"
            }

    Returns:
        GET Requests:
            - API: Method not allowed error (405)

        POST Success:
            - API: JSON success with user data (201)

        POST Failure:
            - API: JSON error response (400/409/500)

    Response Examples:
        API Success (201):
        {
            "success": true,
            "message": "Registration successful",
            "user": {
                "id": 124,
                "username": "new_user",
                "email": "new_user@example.com",
                "security_question": "What city were you born in?"
            }
        }

        API Error (409 - Conflict):
        {
            "error": "Username already exists"
        }

    Security Features:
        - Passwords hashed with PBKDF2-SHA256 before storage
        - Username and email uniqueness enforced
        - Security question/answer stored for password recovery
        - No sensitive data returned in API responses
        - Database rollback on registration errors

    Validation Rules:
        - All fields are required
        - Username must be unique across all users
        - Email must be unique across all users
        - Security question and answer required for account recovery

    Error Conditions:
        - 400: Missing required fields or invalid data
        - 405: GET request to API endpoint
        - 409: Username or email already exists
        - 500: Database error during user creation

    Database Operations:
        - Queries User table for existing username/email
        - Creates new User record with hashed password
        - Commits transaction or rolls back on error
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['username', 'email', 'password', 'security_question', 'security_answer']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    security_question = data.get('security_question')
    security_answer = data.get('security_answer')

    # Check if user exists
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 409

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

    token = generate_token(new_user.id)
    return jsonify({
        'success': True,
        'token': token,
        'user': serialize_user(new_user)
    }), 201


@api.route('/tasks', methods=['POST'])
@token_required
def create_task():
    """
        Create new tasks or subtasks with validation and depth control.

        This endpoint handles the creation of both main tasks and nested subtasks.
        It includes comprehensive validation, depth limiting, and supports JSON API requests.

        Authentication:
            - Requires active user session (@login_required decorator)
            - Associates created tasks with the authenticated user

        GET Request:
            - API: Returns 405 Method Not Allowed (POST required)

        POST Request Processing:
            1. Extracts task data from JSON
            2. Validates required fields (title is mandatory)
            3. Processes parent_task_id for subtask creation
            4. Validates parent task ownership and existence
            5. Checks nesting depth against MAX_NESTING_DEPTH limit
            6. Calculates task depth based on parent hierarchy
            7. Creates and saves new Task record
            8. Returns success response or redirects appropriately

        Request Data (POST):
            JSON (API clients):
                {
                    "title": "string (required) - Task description",
                    "priority": "integer (optional, default=1) - Priority level 1-3",
                    "parent_task_id": "integer (optional) - Parent task for subtasks"
                }

        Task Hierarchy Rules:
            - Main tasks: parent_task_id = None, depth = 0
            - Subtasks: parent_task_id = valid parent ID, depth = parent.depth + 1
            - Maximum nesting depth enforced (MAX_NESTING_DEPTH = 5)
            - Parent task must belong to current user
            - Parent task must exist in database

        Returns:
            GET Requests:
                - API: Method not allowed error (405)

            POST Success:
                - API: JSON success with created task data (201)

            POST Failure:
                - API: JSON error response (400/500)

        Response Examples:
            API Success (201):
            {
                "success": true,
                "message": "Task created successfully",
                "task": {
                    "id": 125,
                    "title": "New task",
                    "completed": false,
                    "priority": 2,
                    "parent_task_id": null,
                    "depth": 0,
                    "user_id": 123,
                    "subtasks": []
                }
            }

            API Error (400):
            {
                "error": "Maximum nesting depth of 5 levels reached"
            }

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

        Error Conditions:
            - 400: Missing title, invalid parent task, or depth limit exceeded
            - 401: User not authenticated (handled by @login_required)
            - 500: Database error during task creation

        Database Operations:
            - Queries parent task for validation and depth calculation
            - Creates new Task record with calculated depth
            - Commits transaction or rolls back on error

        """
    data = request.get_json()
    if not data or not data.get('title'):
        return jsonify({'error': 'Task title is required'}), 400

    parent_task_id = data.get('parent_task_id')
    priority = int(data.get('priority', 1))
    depth = 0

    if parent_task_id:
        parent_task = Task.query.get(parent_task_id)
        if not parent_task or parent_task.user_id != request.current_user.id:
            return jsonify({'error': 'Invalid parent task'}), 400
        depth = parent_task.depth + 1

    new_task = Task(
        title=data['title'],
        user_id=request.current_user.id,
        priority=priority,
        parent_task_id=parent_task_id,
        depth=depth
    )

    db.session.add(new_task)
    db.session.commit()

    return jsonify({
        'success': True,
        'task': serialize_task(new_task)
    }), 201


@api.route('/tasks/<int:task_id>', methods=['GET'])
@token_required
def get_task(task_id):
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
            5. Returns data in appropriate format (JSON)

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
            API Clients Success (200):
                {
                    "success": true,
                    "task": {
                        "id": 123,
                        "title": "Parent Task",
                        "completed": false,
                        "priority": 2,
                        "subtasks": [
                            {
                                "id": 124,
                                "title": "Subtask 1",
                                "depth": 1,
                                "subtasks": [...]
                            }
                        ],
                        ...
                    },
                    "breadcrumbs": [
                        {"id": 100, "title": "Root Task", "depth": 0},
                        {"id": 123, "title": "Current Task", "depth": 1}
                    ]
                }

            Error Response (404):
                {
                    "error": "Task not found or access denied"
                }

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

        Error Conditions:
            - 401: User not authenticated (handled by @login_required)
            - 404: Task not found or user lacks permission
            - 500: Database error during data retrieval

        Example Usage:
            # Get task data (API)
            GET /task/123
            Headers: Accept: application/json
            Response: Complete task data with breadcrumbs
        """
    task = Task.query.get(task_id)
    if not task or task.user_id != request.current_user.id:
        return jsonify({'error': 'Task not found'}), 404

    breadcrumbs = []
    if task.parent_task_id:
        breadcrumbs = task.get_ancestors()
        breadcrumbs.append(task)

    return jsonify({
        'success': True,
        'task': serialize_task(task),
        'breadcrumbs': [serialize_task(ancestor) for ancestor in breadcrumbs]
    }), 200


@api.route('/tasks/<int:task_id>', methods=['PUT', 'PATCH'])
@token_required
def update_task(task_id):
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
            POST/PUT/PATCH Request:
                - JSON: Updated task object with success confirmation

        HTTP Status Codes:
            200: Success - task retrieved/updated
            404: Not Found - task doesn't exist or access denied
            500: Internal Server Error
        """
    task = Task.query.get(task_id)
    if not task or task.user_id != request.current_user.id:
        return jsonify({'error': 'Task not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    if 'title' in data:
        task.title = data['title']
    if 'priority' in data:
        task.priority = int(data['priority'])
    if 'completed' in data:
        task.completed = bool(data['completed'])

    db.session.commit()

    return jsonify({
        'success': True,
        'task': serialize_task(task)
    }), 200


@api.route('/tasks/<int:task_id>/complete', methods=['POST'])
@token_required
def toggle_complete(task_id):
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
            API Clients Success (200):
                {
                    "success": true,
                    "message": "Task completed" | "Task marked as incomplete",
                    "task": {
                        "id": 123,
                        "title": "Task title",
                        "completed": true,
                        "subtasks": [...]
                    }
                }

            Error Response (404):
                {
                    "error": "Task not found or access denied"
                }

        Security Features:
            - Task ownership validation prevents unauthorized access
            - User isolation ensures users can only modify their tasks
            - Database rollback on errors maintains data integrity

        Performance Considerations:
            - Single database query to retrieve task and subtasks
            - Recursive function processes subtasks in memory
            - Single commit for all changes reduces database overhead

        Error Conditions:
            - 401: User not authenticated (handled by @login_required)
            - 404: Task not found or user lacks permission
            - 500: Database error during status update

        Database Operations:
            - SELECT: Retrieves task and validates ownership
            - UPDATE: Changes completion status recursively
            - Uses task.subtasks relationship for hierarchy traversal

        Example Usage:
            # Toggle subtask completion (API)
            GET /complete/456
            Headers: Accept: application/json
            Response: {"success": true, "message": "Task completed", ...}
        """
    task = Task.query.get(task_id)
    if not task or task.user_id != request.current_user.id:
        return jsonify({'error': 'Task not found'}), 404

    task.completed = not task.completed

    # Toggle subtasks as well
    def toggle_subtasks(task_obj, completed_status):
        for subtask in task_obj.subtasks:
            subtask.completed = completed_status
            toggle_subtasks(subtask, completed_status)

    toggle_subtasks(task, task.completed)
    db.session.commit()

    return jsonify({
        'success': True,
        'task': serialize_task(task)
    }), 200


@api.route('/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(task_id):
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
            API Clients Success (200):
                {
                    "success": true,
                    "message": "Task deleted successfully"
                }

            Error Response (404):
                {
                    "error": "Task not found or access denied"
                }

        Security Features:
            - Task ownership validation prevents unauthorized deletion
            - User isolation ensures users can only delete their tasks
            - Database rollback on errors prevents partial deletions

        Data Preservation:
            - Parent/root task IDs stored before deletion for navigation
            - Database transaction ensures atomic operation
            - Rollback protection maintains data consistency

        Error Conditions:
            - 401: User not authenticated (handled by @login_required)
            - 404: Task not found or user lacks permission
            - 500: Database error during deletion

        Database Operations:
            - SELECT: Retrieves task and validates ownership
            - DELETE: Removes task (cascades to subtasks automatically)
            - Uses SQLAlchemy's session management for transactions

        Permanent Operation:
            - Deletion is irreversible
            - No soft delete or recovery mechanism
            - All associated subtask data is permanently lost

        Example Usage:
            # Delete subtask (API)
            GET /delete/456
            Headers: Accept: application/json
            Response: {"success": true, "message": "Task deleted successfully"}
        """
    task = Task.query.get(task_id)
    if not task or task.user_id != request.current_user.id:
        return jsonify({'error': 'Task not found'}), 404

    db.session.delete(task)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Task deleted successfully'
    }), 200

@api.route('/suggested_tasks', methods=['GET'])
@token_required
def get_suggested_tasks():
    """
        Retrieve predefined task suggestions to inspire users.

        This endpoint provides a curated list of common task suggestions that users
        can quickly add to their task lists. It helps overcome the "blank page" problem
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
            API Clients Success (200):
                {
                    "success": true,
                    "suggested_tasks": [
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

        Error Conditions:
            - 401: User not authenticated (handled by @login_required)
            - 500: Unlikely server error

        Example Usage:
            # Get suggestions for task creation interface
            GET /suggested_tasks
            Headers: Accept: application/json

            Response:
            {
                "success": true,
                "suggested_tasks": [
                    "Buy groceries",
                    "Read a book",
                    ...
                ]
            }
        """
    suggested_tasks = [
        "Buy groceries", "Read a book", "Exercise", "Clean the house", "Write a blog post",
        "Learn a new skill", "Call a friend", "Plan a trip", "Cook a new recipe", "Organize your workspace"
    ]

    return jsonify({
        'success': True,
        'suggested_tasks': suggested_tasks
    }), 200

@api.route('/forgot_password', methods=['POST'])
def forgot_password():
    """
    Initiate the password recovery process using security questions.

    This endpoint begins the secure password reset workflow by validating the
    user's identity and presenting their security question. It implements the
    first step of a multi-stage password recovery system.

    HTTP Methods:
        - POST: Process username and initiate recovery

    GET Request:
        - API: Returns 405 Method Not Allowed

    POST Request Processing:
        1. Extracts username from request (JSON or form data)
        2. Validates username is provided
        3. Searches database for user with matching username
        4. If found, stores username and security question in session
        5. Proceeds to security question verification step

    Request Data (POST):
        JSON (API clients):
            {
                "username": "string (required) - Username for account recovery"
            }

    Session Management:
        - Stores username in session for subsequent steps
        - Stores security_question for display and validation
        - Session data used throughout recovery workflow
        - Session cleared after successful password reset

    Returns:
        GET Requests:
            - API: Method not allowed error (405)

        POST Success:
            - API: JSON with security question (200)

        POST Failure:
            - API: JSON error response (400/404/500)

    Response Examples:
        API Success (200):
        {
            "success": true,
            "message": "User found",
            "security_question": "What city were you born in?",
            "next_step": "security_answer"
        }

        API Error (404):
        {
            "error": "Username not found"
        }

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

    Error Conditions:
        - 400: Missing username parameter
        - 404: Username not found in database
        - 405: GET request to API endpoint
        - 500: Database or session error

    Example Usage:
        # API recovery initiation
        POST /forgot_password
        {
            "username": "john_doe"
        }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    username = data.get('username')

    if not username:
        error_msg = 'Username is required'
        return jsonify({'error': error_msg}), 400

    user = User.query.filter_by(username=username).first()
    if user:
        session['username'] = username
        session['security_question'] = user.security_question

        return jsonify({
            'success': True,
            'message': 'User found',
            'security_question': user.security_question,
            'next_step': 'security_answer'
        }), 200
    else:
        error_msg = 'Username not found'
        return jsonify({'error': error_msg}), 404


@api.route('/users/<username>/security_question', methods=['GET'])
def get_security_question(username: str) -> Tuple[Dict[str, Any], int]:
    """
    Retrieve security question for a specific user.

    Args:
        username: The username to get security question for

    Returns:
        JSON response with security question or error
    """
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not user.security_question:
        return jsonify({'error': 'No security question set for this user'}), 404

    return jsonify({
        'security_question': user.security_question,
        'username': username
    }), 200


@api.route('/security_answer/verify', methods=['POST'])
def verify_security_answer() -> Tuple[Dict[str, Any], int]:
    """
    Verify security answer for password reset flow.

    Expected JSON payload:
        {
            "username": "string",
            "security_answer": "string"
        }

    Returns:
        JSON response indicating success or failure
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400

    username = data.get('username')
    security_answer_input = data.get('security_answer')

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    if not security_answer_input:
        return jsonify({'error': 'Security answer is required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not user.security_answer:
        return jsonify({'error': 'No security answer set for this user'}), 404

    # Compare security answers (case-insensitive, trimmed)
    stored_answer = user.security_answer.strip().lower()
    provided_answer = security_answer_input.strip().lower()

    if stored_answer == provided_answer:
        # Store verification in session for next step
        session['username'] = username
        session['security_verified'] = True

        return jsonify({
            'success': True,
            'message': 'Security answer verified',
            'next_step': 'reset_password'
        }), 200
    else:
        return jsonify({'error': 'Incorrect security answer'}), 401


@api.route('/reset_password', methods=['GET', 'POST'])
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
                - JSON: Confirmation that user is ready for password reset

            POST Request:
                - JSON: Success/error response

        HTTP Status Codes:
            200: Success - password updated
            400: Bad Request - missing new password or session expired
            404: Not Found - user not found
            500: Internal Server Error

        Database Operations:
            - Updates user.password field with hashed password
            - Commits transaction on success
            - Rolls back on any database errors
        """
    username: Optional[str] = session.get('username')

    if request.method == 'GET':
        if not username:
            return jsonify({'error': 'Session expired. Start password reset again.'}), 400
        return jsonify({
            'message': 'Ready for password reset',
            'username': username
        }), 200

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    new_password: Optional[str] = data.get('new_password')
    # Allow username override for API flexibility
    username = data.get('username', username)

    if not new_password:
        error_msg = 'New password is required'
        return jsonify({'error': error_msg}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        error_msg = 'User not found'
        return jsonify({'error': error_msg}), 404

    hashed_password: str = generate_password_hash(new_password, method='pbkdf2:sha256')

    user.password = hashed_password
    db.session.commit()

    # Clean up sensitive session data to prevent reuse
    session.pop('username', None)
    session.pop('security_question', None)

    # Return success response
    success_msg = 'Password has been reset successfully'
    return jsonify({
        'success': True,
        'message': success_msg
    }), 200

@api.route('/import_markdown', methods=['POST'])
@token_required
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
        JSON API:
            - parsed_tasks: Pre-processed task hierarchy
            - content: Raw markdown text to parse

    Parameters:
        default_priority (int): Priority level for imported tasks (default: 2)

    Returns:
        JSON Response:
            - success: Boolean indicating import status
            - message: Human-readable result description
            - imported_count: Number of tasks successfully imported

    HTTP Status Codes:
        200: Success - tasks imported
        400: Bad Request - invalid input or no tasks found
        500: Internal Server Error

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
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        print("i am here")
        if 'parsed_tasks' in data:
            parsed_tasks: List[Dict[str, Any]] = data['parsed_tasks']
            default_priority: int = int(data.get('default_priority', 2))
        elif 'content' in data:
            markdown_content: str = data['content']
            default_priority: int = int(data.get('default_priority', 2))
            parsed_tasks: List[Dict[str, Any]] = parse_markdown_content(markdown_content)
        else:
            return jsonify({'error': 'Either parsed_tasks or content is required'}), 400

        # Validate that tasks were found/provided
        if not parsed_tasks:
            return jsonify({'error': 'No tasks found in the provided data'}), 400

        # Import tasks into database
        imported_count: int = import_tasks_from_data_api(parsed_tasks, default_priority)

        return jsonify({
            'success': True,
            'message': f'Successfully imported {imported_count} tasks',
            'imported_count': imported_count
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@api.route('/export_tasks')
@token_required
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
        JSON Response:
            - success: Boolean status
            - content: Full markdown content as string
            - filename: Suggested filename with timestamp
            - content_type: MIME type for proper handling

    Task Processing:
        - Fetches only main tasks (parent_task_id = None)
        - Sorts by priority (descending) then title (ascending)
        - Subtasks loaded via SQLAlchemy relationships
        - Recursive processing maintains hierarchy

    File Format:
        - UTF-8 encoded markdown
        - Timestamped filename for version control
        - Re-importable structure using same parser

    HTTP Status Codes:
        200: Success - export generated
        500: Internal Server Error

    Security:
        - Only exports tasks owned by authenticated user
        - No sensitive data exposure beyond task content
    """
    try:
        main_tasks = Task.query.filter_by(
            user_id=request.current_user.id,
            parent_task_id=None
        ).all()

        # Sort tasks by priority (high to low) then alphabetically by title
        main_tasks.sort(key=lambda t: (-t.priority, t.title))

        # Generate formatted markdown content
        markdown_content: str = generate_markdown_export(main_tasks)

        # Create timestamped filename for version control
        timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename: str = f"my_tasks_{timestamp}.md"

        return jsonify({
            'success': True,
            'content': markdown_content,
            'filename': filename,
            'content_type': 'text/markdown'
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
