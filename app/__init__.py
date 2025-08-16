from datetime import timedelta
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
import os
from dotenv import load_dotenv

load_dotenv()
csrf = CSRFProtect()
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()


@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))


def create_app(config_class=None):
    app = Flask(__name__)

    if config_class:
        app.config.from_object(config_class)
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
        app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_pre_ping': True,
            'pool_recycle': 1800,
            'pool_size': 5,
            'max_overflow': 10,
            'connect_args': {
                'sslmode': 'require',
                'connect_timeout': 10,
                'keepalives_idle': 600,
                'keepalives_interval': 30,
                'keepalives_count': 3,
                'tcp_user_timeout': 1000
            }
        }

    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    csrf.init_app(app)

    # Register blueprints within app context
    with app.app_context():
        from . import routes
        app.register_blueprint(routes.main)

        from .api import api
        app.register_blueprint(api)

        # Exempt API blueprint from CSRF protection
        csrf.exempt(api)

        # Force engine disposal after configuration is complete
        # This ensures new connections use the updated settings
        if hasattr(db, 'engine') and db.engine:
            db.engine.dispose()

    return app