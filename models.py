from . import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(150))
    uuid = db.Column(db.String(100))
    last_login = db.Column(db.DateTime(timezone=True))
    auth_key = db.Column(db.String(64))
    mail_auth_key = db.Column(db.String(64))
    is_authed = db.Column(db.Boolean, default=False)
    is_privilleged = db.Column(db.Boolean, default=False)

class Announcements(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_by = db.Column(db.String(50))
    created_by_uuid = db.Column(db.String(100))
    created_on = db.Column(db.DateTime(timezone=True))
    content = db.Column(db.String(10000))

class WOL_logs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.DateTime(timezone=True))
    user_id = db.Column(db.Integer)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_local = db.Column(db.Boolean, default=False)
    ip = db.Column(db.String(15))
    public_ip = db.Column(db.String(50))
    mac = db.Column(db.String(20))
    current_status = db.Column(db.String(20))

class Server_status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.DateTime(timezone=True))
    server_id = db.Column(db.Integer)
    status = db.Column(db.String(50))

class Game_server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer)
    port = db.Column(db.String(10))
    updated_at = db.Column(db.DateTime(timezone=True))
    include_schedule = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(50))

    