from app import create_app, db
from dotenv import load_dotenv
import os

load_dotenv()
class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ['TEST_SQLALCHEMY_DATABASE_URI']
    SECRET_KEY = os.environ['TEST_SECRET_KEY']

def create_test_app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
    return app