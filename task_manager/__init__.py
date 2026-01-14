from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Initialize extensions (instances, not bound to an app yet)
db = SQLAlchemy()


def create_app(config_object=None):
    app = Flask(__name__, instance_relative_config=False)

    # Load default config, allow override via argument
    app.config.from_object('task_manager.config.DefaultConfig')
    if config_object:
        app.config.from_object(config_object)

    # Initialize extensions with app
    db.init_app(app)

    with app.app_context():
        # Import parts of our application
        from . import models  # registers models with SQLAlchemy
        from .routes import main_bp

        # Register blueprints
        app.register_blueprint(main_bp)

        # Ensure DB exists
        db.create_all()

    return app
