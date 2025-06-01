from flask import Blueprint, render_template, redirect, url_for, request, session, jsonify, flash
from flask_login import login_user, login_required, logout_user, current_user
import bcrypt
from app import db
from app.models import User, Task
import json
import os
from werkzeug.utils import secure_filename

main = Blueprint('main', __name__)

MAX_NESTING_DEPTH = 5  # Maximum depth for nested subtasks


@main.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            login_user(user)
            session.permanent = True
            return redirect(url_for('main.index'))
        else:
            error_message = 'Login Unsuccessful. Please check username and password'
    return render_template('login.html', error_message=error_message)


@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        security_question = request.form.get('security_question')
        security_answer = request.form.get('security_answer')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=username, email=email, password=hashed_password, security_question=security_question,
                        security_answer=security_answer)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('main.login'))
    return render_template('register.html')


@main.route('/')
@login_required
def index():
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
    # Debug: Print all form data
    print("=== ADD ROUTE DEBUG ===")
    print(f"Request method: {request.method}")
    print(f"Form data: {request.form}")

    title = request.form.get('title')
    priority = int(request.form.get('priority', 1))
    parent_task_id = request.form.get('parent_task_id')

    print(f"Title: {title}")
    print(f"Priority: {priority}")
    print(f"Parent Task ID: {parent_task_id}")
    print(f"Parent Task ID type: {type(parent_task_id)}")

    if not title:
        flash('Task title is required!', 'error')
        return redirect(url_for('main.index'))

    # Convert parent_task_id to int if it exists and is not empty
    if parent_task_id and parent_task_id.strip():
        try:
            parent_task_id = int(parent_task_id)
            print(f"Converted parent_task_id to int: {parent_task_id}")
        except (ValueError, TypeError):
            print(f"Failed to convert parent_task_id to int: {parent_task_id}")
            parent_task_id = None
    else:
        parent_task_id = None

    # Calculate depth
    depth = 0
    if parent_task_id:
        parent_task = Task.query.get(parent_task_id)
        print(f"Parent task found: {parent_task}")

        if parent_task and parent_task.user_id == current_user.id:
            print(f"Parent task belongs to current user")
            # Check if we can add subtask (depth limit)
            if not parent_task.can_add_subtask(MAX_NESTING_DEPTH):
                flash(f'Maximum nesting depth of {MAX_NESTING_DEPTH} levels reached!', 'error')
                return redirect(url_for('main.task_details', task_id=parent_task_id))
            depth = parent_task.depth + 1
            print(f"Subtask depth will be: {depth}")
        else:
            print(f"Invalid parent task or access denied")
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

    print(f"Creating task: {new_task.title}")
    print(f"Task parent_task_id: {new_task.parent_task_id}")
    print(f"Task depth: {new_task.depth}")

    db.session.add(new_task)
    db.session.commit()

    print(f"Task created successfully with ID: {new_task.id}")
    print("=== END DEBUG ===")

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
    task = db.session.get(Task, task_id)
    if task and task.user_id == current_user.id:
        task.completed = not task.completed
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
    task = Task.query.get_or_404(task_id)

    # Ensure the task belongs to the current user
    if task.user_id != current_user.id:
        return redirect(url_for('main.index'))

    # Get all subtasks with their subtasks loaded
    def load_subtasks_recursive(parent_task):
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
    existing_usernames = [user.username for user in User.query.all()]
    username = request.form.get('username')
    if username in existing_usernames:
        return jsonify({'exists': True})
    return jsonify({'exists': False})


@main.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
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
    username = session.get('username')
    security_question = session.get('security_question')
    if request.method == 'POST':
        security_answer = request.form.get('security_answer')
        user = User.query.filter_by(username=username).first()
        if user and user.security_answer == security_answer:
            return jsonify({'status': 'success', 'redirect_url': url_for('main.reset_password')})
        else:
            return jsonify({'status': 'danger', 'message': 'Incorrect security answer.'})
    return render_template('security_answer.html', security_question=security_question)


@main.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        username = session.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            user.password = hashed_password
            db.session.commit()
            return jsonify({'message': 'Your password has been reset successfully.', 'status': 'success'})
    return render_template('reset_password.html')


@main.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit(task_id):
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
    priority = request.form.get('priority', 1)
    new_task = Task(title=task_title, user_id=current_user.id, priority=priority, depth=0)
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('main.index'))


@main.route('/import_markdown', methods=['POST'])
def import_markdown():
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
    """Check if the uploaded file has an allowed extension"""
    ALLOWED_EXTENSIONS = {'md', 'txt'}
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def parse_markdown_content(content):
    """Parse markdown content and extract tasks with nested structure"""
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
    """Import tasks from parsed data into the database with nested structure"""
    imported_count = 0

    def create_task_recursive(task_data, parent_id=None, current_depth=0):
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