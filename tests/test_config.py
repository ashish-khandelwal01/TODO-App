from app import create_app, db

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SECRET_KEY = 'test_secret_key'

def create_test_app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
    return app