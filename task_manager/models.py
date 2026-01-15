import datetime
from . import db


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
    assigned_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    time_logs = db.relationship('TimeLog', backref='task', lazy=True)
    
    def get_time_to_assign(self):
        if self.assigned_at:
            delta = self.assigned_at - self.created_at
            return round(delta.total_seconds() / 3600, 2)
        return None
    
    def get_completion_time(self):
        if self.assigned_at and self.completed_at:
            delta = self.completed_at - self.assigned_at
            return round(delta.total_seconds() / 3600, 2)
        return None
    
    def get_total_task_time(self):
        if self.completed_at:
            delta = self.completed_at - self.created_at
            return round(delta.total_seconds() / 3600, 2)
        return None


class TimeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hours = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    date_logged = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
