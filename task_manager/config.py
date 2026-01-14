import os


class DefaultConfig:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me-in-prod')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///task_manager.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
