import datetime
import jwt
from functools import wraps
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from .models import User, Task, TimeLog
from . import db

main_bp = Blueprint('main', __name__)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except Exception:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            if current_user.role not in roles:
                return jsonify({'message': 'Permission denied!'}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator


@main_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password, role=data.get('role', 'User'))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully!'}), 201


@main_bp.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    user = User.query.filter_by(username=auth['username']).first()
    if user and check_password_hash(user.password, auth['password']):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, current_app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials!'}), 401


@main_bp.route('/tasks', methods=['POST'])
@token_required
@role_required(['Admin', 'Manager'])
def create_task(current_user):
    data = request.get_json()
    new_task = Task(title=data['title'], description=data.get('description'))
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message': 'Task created!', 'task_id': new_task.id})


@main_bp.route('/tasks/<int:task_id>/assign', methods=['PUT'])
@token_required
@role_required(['Admin', 'Manager'])
def assign_task(current_user, task_id):
    data = request.get_json()
    task = Task.query.get_or_404(task_id)
    task.user_id = data['user_id']
    db.session.commit()
    return jsonify({'message': f'Task assigned to user {data["user_id"]}'})


@main_bp.route('/tasks/<int:task_id>/status', methods=['PUT'])
@token_required
def update_task_status(current_user, task_id):
    data = request.get_json()
    task = Task.query.get_or_404(task_id)

    if current_user.role not in ['Admin', 'Manager'] and task.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized'}), 403

    task.status = data['status']
    db.session.commit()
    return jsonify({'message': 'Status updated'})


@main_bp.route('/tasks/<int:task_id>/log-time', methods=['POST'])
@token_required
def log_time(current_user, task_id):
    data = request.get_json()
    task = Task.query.get_or_404(task_id)

    new_log = TimeLog(
        hours=data['hours'],
        description=data.get('description'),
        task_id=task.id,
        user_id=current_user.id
    )
    db.session.add(new_log)
    db.session.commit()
    return jsonify({'message': 'Time logged successfully'})


@main_bp.route('/my-summary', methods=['GET'])
@token_required
def get_summary(current_user):
    logs = TimeLog.query.filter_by(user_id=current_user.id).all()
    total_hours = sum(log.hours for log in logs)

    tasks_assigned = Task.query.filter_by(user_id=current_user.id).all()
    task_list = [{
        'id': t.id,
        'title': t.title,
        'status': t.status,
        'hours_spent': sum(l.hours for l in t.time_logs if l.user_id == current_user.id)
    } for t in tasks_assigned]

    return jsonify({
        'user': current_user.username,
        'total_hours_logged': total_hours,
        'tasks': task_list
    })


@main_bp.route('/admin/generate-reports', methods=['POST'])
@token_required
@role_required(['Admin'])
def generate_reports(current_user):
    all_logs = TimeLog.query.all()
    report = {}
    for log in all_logs:
        user = User.query.get(log.user_id).username
        report[user] = report.get(user, 0) + log.hours

    return jsonify({
        'status': 'Daily Summary Generated',
        'data': report
    })
