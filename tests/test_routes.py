import pytest
import os
from flask import url_for
from flask_testing import TestCase
from app import db
from app.models import User, Task
from .test_config import create_test_app
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import CSRFProtect
import bcrypt

class TestRoutes(TestCase):
    def create_app(self):
        app = create_test_app()
        csrf = CSRFProtect()
        csrf.init_app(app)
        return app

    def setUp(self):
        db.create_all()
        username = os.environ.get('TEST_USERNAME')
        email = os.environ.get('TEST_EMAIL')
        password = os.environ.get('TEST_PASSWORD')
        security_question = os.environ.get('TEST_SECURITY_QUESTION')
        security_answer = os.environ.get('TEST_SECURITY_ANSWER')

        if not all([username, email, password, security_question, security_answer]):
            raise EnvironmentError("One or more required environment variables are missing")
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.user = User(
            username=username,
            email=email,
            password=hashed_password,
            security_question=security_question,
            security_answer=security_answer
        )
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def assert_redirects(self, response, location):
        expected_location = urlparse(location).path
        actual_location = urlparse(response.location).path
        self.assertEqual(actual_location, expected_location)

    def get_csrf_token(self, response):
        try:
            return response.data.decode().split('name="csrf_token" value="')[1].split('"')[0]
        except IndexError:
            raise ValueError("CSRF token not found in the response")

    def login(self):
        response = self.client.get(url_for('main.login'))
        csrf_token = self.get_csrf_token(response)
        self.client.post(url_for('main.login'), data=dict(
            username='testuser',
            password='testpassword',
            csrf_token=csrf_token
        ))

    def test_login(self):
        response = self.client.get(url_for('main.login'))
        csrf_token = self.get_csrf_token(response)
        response = self.client.post(url_for('main.login'), data=dict(
            username='testuser',
            password='testpassword',
            csrf_token=csrf_token
        ))
        self.assert_redirects(response, url_for('main.index'))

    def test_register(self):
        response = self.client.get(url_for('main.register'))
        csrf_token = self.get_csrf_token(response)
        response = self.client.post(url_for('main.register'), data=dict(
            username='newuser',
            email='new@example.com',
            password='newpassword',
            confirm_password='newpassword',
            security_question='Test question?',
            security_answer='Test answer',
            csrf_token=csrf_token
        ))
        self.assert_redirects(response, url_for('main.login'))

    def test_add_task(self):
        self.login()
        response = self.client.get(url_for('main.add'))
        if response.status_code == 302:
            response = self.client.get(response.location)
        csrf_token = self.get_csrf_token(response)
        response = self.client.post(url_for('main.add'), data=dict(
            title='New Task',
            priority=1,
            csrf_token=csrf_token
        ))
        self.assert_redirects(response, url_for('main.index'))
        task = Task.query.filter_by(title='New Task').first()
        assert task is not None

    def test_complete_task(self):
        self.login()
        task = Task(title='Incomplete Task', user_id=self.user.id)
        db.session.add(task)
        db.session.commit()
        response = self.client.get(url_for('main.complete', task_id=task.id))
        self.assert_redirects(response, url_for('main.index'))
        task = Task.query.get(task.id)
        assert task.completed is True

    def test_delete_task(self):
        self.login()
        task = Task(title='Task to Delete', user_id=self.user.id)
        db.session.add(task)
        db.session.commit()
        response = self.client.get(url_for('main.delete', task_id=task.id))
        self.assert_redirects(response, url_for('main.index'))
        task = db.session.get(Task, task.id)
        assert task is None

    def test_forgot_password(self):
        response = self.client.get(url_for('main.forgot_password'))
        csrf_token = self.get_csrf_token(response)
        response = self.client.post(url_for('main.forgot_password'), data=dict(
            username='testuser',
            csrf_token=csrf_token
        ))
        self.assert_redirects(response, url_for('main.security_answer'))

if __name__ == '__main__':
    pytest.main()