from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_apscheduler import APScheduler

import json
from os import path
from datetime import timedelta

from .scheduler_utils import checkEmptyServersScheduler

db = SQLAlchemy()

if not path.exists('website/config.json'):
    raise Exception("No config file found")

cfg = json.load(open('website/config.json'))['settings']

DB_NAME = cfg['DB_FILENAME']
SERVER_IP = cfg['SERVER_IP']
OFFICIAL_DOMAIN = cfg['OFFICIAL_DOMAIN']
SMTP_FROM = cfg['SMTP_FROM']
SMTP_LOGIN = cfg['SMTP_LOGIN']
SMTP_PASSWORD = cfg['SMTP_PASSWORD']


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = cfg['SECRET_KEY']
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Announcements, Server, Server_status, Game_server, WOL_logs

    with app.app_context():
        if not path.exists('instance/' + DB_NAME):
            db.create_all()
            print('Created Database')

        if (not Server.query.filter_by(ip=SERVER_IP).first()):
            new_server = Server(ip=SERVER_IP, public_ip=OFFICIAL_DOMAIN, current_status='Offline', mac='08:60:6e:f0:49:9b', is_local=True)
            db.session.add(new_server)
            db.session.commit()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=1)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    scheduler = APScheduler()

    @scheduler.task('interval', id='game_server_maintenance', seconds=1800)
    def game_server_maintenance():
        with scheduler.app.app_context():
            checkEmptyServersScheduler(db, Server, Game_server, SERVER_IP)


    scheduler.init_app(app)
    scheduler.start()


    return app