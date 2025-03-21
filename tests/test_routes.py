import pytest
from flask import url_for
from flask_testing import TestCase
from app import db
from app.models import User, Task
from .test_config import create_test_app
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash

class TestRoutes(TestCase):
    def create_app(self):
        return create_test_app()

    def setUp(self):
        db.create_all()
        self.user = User(
            username='testuser',
            email='test@example.com',
            password=generate_password_hash('testpassword', method='pbkdf2:sha256'),
            security_question='Test question?',
            security_answer='Test answer'
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

    def login(self):
        self.client.post(url_for('main.login'), data=dict(
            username='testuser',
            password='testpassword'
        ))

    def test_login(self):
        response = self.client.post(url_for('main.login'), data=dict(
            username='testuser',
            password='testpassword'
        ))
        self.assert_redirects(response, url_for('main.index'))

    def test_register(self):
        response = self.client.post(url_for('main.register'), data=dict(
            username='newuser',
            email='new@example.com',
            password='newpassword',
            confirm_password='newpassword',
            security_question='Test question?',
            security_answer='Test answer'
        ))
        self.assert_redirects(response, url_for('main.login'))

    def test_add_task(self):
        self.login()
        response = self.client.post(url_for('main.add'), data=dict(
            title='New Task',
            priority=1
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
        response = self.client.post(url_for('main.forgot_password'), data=dict(
            username='testuser'
        ))
        self.assert_redirects(response, url_for('main.security_answer'))

if __name__ == '__main__':
    pytest.main()