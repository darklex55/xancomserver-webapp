from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from flask_apscheduler import APScheduler

import requests
from mcstatus import MinecraftServer
from datetime import datetime

db = SQLAlchemy()
DB_NAME = 'database.db'
SERVER_IP = '192.168.1.4'
OFFICIAL_IP = 'xancomserver.ddns.me'

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'kara2004'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Server, Game_server

    create_database(app)

    with app.app_context():
        Server.query.filter_by(ip='192.168.1.7').delete()
        db.session.commit()

        if (not Server.query.filter_by(ip=SERVER_IP).first()):
            new_server = Server(ip=SERVER_IP, public_ip='xancomserver.ddns.me', current_status='Offline', mac='08:60:6e:f0:49:9b', is_local=True)
            db.session.add(new_server)
            db.session.commit()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    scheduler = APScheduler()

    @scheduler.task('interval', id='game_server_maintenance', seconds=1800)
    def game_server_maintenance():
        with scheduler.app.app_context():
            ips = []
            ports = []
            players = []
            statuses = []
            dirs = []
            i=0
            try:
                res = requests.get('http://' + SERVER_IP + '/getMCServers', timeout=2)
                if res.status_code==200:
                    res = res.json()
                    all_ports = res.get('answer')[1]

                    for port in all_ports:
                        server = MinecraftServer.lookup(SERVER_IP+':'+str(port))
                        stat = 1
                        player = 0
                        dir = ''
                        
                        try:
                            stats = server.status()
                            player = stats.players.online
                            stat = 0
                            dir = res.get('answer')[2][i]
                        except:
                            stat=1

                        ips.append(SERVER_IP)
                        ports.append(str(port))
                        players.append(player)
                        statuses.append(stat)
                        dirs.append(dir)
                        i+=1
            except:
                print(' Scheduler - Could not communicate with the server.')

            for i in range(len(ips)):
                server_record = Server.query.filter_by(ip=ips[i]).first()
                if server_record:
                    game_server_record = Game_server.query.filter_by(server_id=server_record.id).filter_by(port=ports[i]).first()
                    if game_server_record:
                        if game_server_record.include_schedule:
                            if game_server_record.status == 'offline':
                                if players[i]>0:
                                    game_server_record.status = 'schedule_green'
                                    db.session.commit()
                                elif players[i]==0 and statuses[i]==0:
                                    game_server_record.status = 'schedule_yellow'
                                    db.session.commit()
                                else:
                                    game_server_record.status = 'offline'
                                    db.session.commit()

                            elif game_server_record.status == 'schedule_green' or (game_server_record.status == 'offline' and players[i]<1):
                                if players[i]<1:
                                    game_server_record.status = 'schedule_yellow'
                                    db.session.commit()

                            elif game_server_record.status == 'schedule_yellow':
                                if players[i]>0:
                                    game_server_record.status = 'schedule_green'
                                    db.session.commit()
                                else:
                                    game_server_record.status = 'offline'
                                    db.session.commit()
                                    if statuses[i]==0:
                                        try:
                                            requests.get('http://'+SERVER_IP+'/shutoff_mc_server?name='+dirs[i], timeout=1)
                                        except:
                                            print('Could not send shutdown command for game server')

                            print('Record Updated: ' + str(ports[i]) + ' - ' + game_server_record.status)
                            
                        
                    else:
                        new_status = 'schedule_yellow'
                        if players[i]>0:
                            new_status = 'schedule_green'
                        if statuses[i]==1:
                            new_status = 'offline'

                        new_record = Game_server(server_id = server_record.id, port=ports[i], updated_at = datetime.now(), include_schedule = True, status=new_status)
                        db.session.add(new_record)
                        db.session.commit()

                        print('New Record: ' + str(ports[i]) + ' - ' + new_status)


    scheduler.init_app(app)
    scheduler.start()


    return app

def create_database(app):
    if not path.exists('website/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database')
