from datetime import timedelta
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_migrate import Migrate

csrf = CSRFProtect()
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()  # Make sure this line exists


@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))


def create_app(config_class=None):
    app = Flask(__name__)
    if config_class:
        app.config.from_object(config_class)
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
        app.config['SECRET_KEY'] = '1724f3332fa61e5c88f592c3d4cdbf9be2b0663f2f91252c9a332a81ed6bead7'

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    csrf.init_app(app)

    with app.app_context():
        from . import routes
        app.register_blueprint(routes.main)
        # db.create_all()

    return app