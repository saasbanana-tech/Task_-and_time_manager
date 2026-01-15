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

    db.init_app(app)

    with app.app_context():
        from . import models 
        from .routes import main_bp

        app.register_blueprint(main_bp)
        
        db.create_all()

    return app
