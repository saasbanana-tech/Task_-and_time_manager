from flask import Flask, request, jsonify
import datetime
import jwt
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='User') 
    tasks = db.relationship('Task', backref='assignee', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='Open')  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    time_logs = db.relationship('TimeLog', backref='task', lazy=True)

class TimeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hours = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    date_logged = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            # Expected format: "Bearer <token>"
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
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



@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password, role=data.get('role', 'User'))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully!'}), 201

@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    user = User.query.filter_by(username=auth['username']).first()
    if user and check_password_hash(user.password, auth['password']):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/tasks', methods=['POST'])
@token_required
@role_required(['Admin', 'Manager'])
def create_task(current_user):
    data = request.get_json()
    new_task = Task(title=data['title'], description=data.get('description'))
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message': 'Task created!', 'task_id': new_task.id})

@app.route('/tasks/<int:task_id>/assign', methods=['PUT'])
@token_required
@role_required(['Admin', 'Manager'])
def assign_task(current_user, task_id):
    data = request.get_json()
    task = Task.query.get_or_404(task_id)
    task.user_id = data['user_id']
    db.session.commit()
    return jsonify({'message': f'Task assigned to user {data["user_id"]}'})

@app.route('/tasks/<int:task_id>/status', methods=['PUT'])
@token_required
def update_task_status(current_user, task_id):
    data = request.get_json()
    task = Task.query.get_or_404(task_id)
    
    if current_user.role not in ['Admin', 'Manager'] and task.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized'}), 403
    
    task.status = data['status']
    db.session.commit()
    return jsonify({'message': 'Status updated'})

@app.route('/tasks/<int:task_id>/log-time', methods=['POST'])
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

@app.route('/my-summary', methods=['GET'])
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

@app.route('/admin/generate-reports', methods=['POST'])
@token_required
@role_required(['Admin'])
def generate_reports(current_user):
    # In a real app, this would use Celery or APScheduler
    # Here we just calculate and return it as a simulation
    all_logs = TimeLog.query.all()
    report = {}
    for log in all_logs:
        user = User.query.get(log.user_id).username
        report[user] = report.get(user, 0) + log.hours
    
    return jsonify({
        'status': 'Daily Summary Generated',
        'data': report
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)