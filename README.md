# Task_-and_time_manager

This project is a Flask-based Task and Time Manager.

## Project layout

- `task_manager/` — application package (factory, models, routes, config)
- `app.py` — development entrypoint (imports and runs app from package)
- `wsgi.py` — production WSGI entrypoint
- `requirements.txt` — Python dependencies
- `tests/` — basic tests

## Running (development)

1. Install dependencies: `pip install -r requirements.txt`
2. Set `SECRET_KEY` environment variable for production-like behavior (optional)
3. Run: `python app.py`

## Testing

Run tests locally with:

```bash
pip install -r requirements.txt
pip install pytest
pytest
```

## Notes for production

- Use `wsgi.py` with Gunicorn or another WSGI server.
- Configure `SECRET_KEY` and `DATABASE_URL` via environment variables.
- For background jobs or scheduled reports, integrate a task queue (Celery, RQ) or scheduler (APScheduler).
A backend system that allows users to create, assign, and track tasks along with the time spent on them
