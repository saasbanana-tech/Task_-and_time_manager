import pytest
from task_manager import create_app


def test_create_app():
    app = create_app()
    assert app is not None
    assert 'SQLALCHEMY_DATABASE_URI' in app.config
