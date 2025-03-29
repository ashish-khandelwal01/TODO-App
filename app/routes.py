from flask import Blueprint, render_template, redirect, url_for, request, session, jsonify
from flask_login import login_user, login_required, logout_user, current_user
import bcrypt
from app import db
from app.models import User, Task

main = Blueprint('main', __name__)


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

    if filter_by:
        tasks = Task.query.filter_by(user_id=current_user.id, priority=filter_by).all()
    else:
        tasks = Task.query.filter_by(user_id=current_user.id).all()

    if sort_by == 'priority':
        tasks.sort(key=lambda task: task.priority, reverse=True)
    else:
        tasks.sort(key=lambda task: getattr(task, sort_by))

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
    return render_template('index.html', tasks=tasks, suggested_tasks=suggested_tasks, sort_by=sort_by, filter_by=filter_by)

@main.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    title = request.form.get('title')
    priority = request.form.get('priority', 1)
    if title:
        new_task = Task(title=title, user_id=current_user.id, priority=priority)
        db.session.add(new_task)
        db.session.commit()
    return redirect(url_for('main.index'))

@main.route('/complete/<int:task_id>')
@login_required
def complete(task_id):
    task = db.session.get(Task, task_id)
    if task:
        task.completed = not task.completed
        db.session.commit()
    return redirect(url_for('main.index'))

@main.route('/delete/<int:task_id>')
@login_required
def delete(task_id):
    task = db.session.get(Task, task_id)
    if task:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('main.index'))

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
    if request.method == 'POST':
        task.title = request.form.get('title')
        task.priority = request.form.get('priority')
        db.session.commit()
        return redirect(url_for('main.index'))
    return render_template('edit_task.html', task=task)

@main.route('/add_suggested/<string:task_title>', methods=['POST'])
@login_required
def add_suggested(task_title):
    priority = request.form.get('priority', 1)
    new_task = Task(title=task_title, user_id=current_user.id, priority=priority)
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('main.index'))

