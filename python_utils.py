from datetime import datetime

from flask_login import current_user
from .models import User, db, Announcements, Server, Server_status, Game_server
from sqlalchemy import desc
from mcstatus import JavaServer
from hashlib import sha1, sha256
from pyotp import totp, random_base32
from base64 import b64encode
from io import BytesIO
import qrcode


import requests
import os

from . import SERVER_IP, OFFICIAL_DOMAIN


def getCurrentDatetimeFormated():
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def getDatetimeFormated(dt):
    if dt is None:
        return '-'
    return dt.strftime("%d/%m/%Y %H:%M:%S")

def getDatetimeFormatedNoSeconds(dt):
    if dt is None:
        return '-'
    return dt.strftime("%d/%m/%Y %H:%M")

def produceHashFromText(text):
    text = text.encode('UTF-8')
    return sha256(text).hexdigest()

def getOTPKeyFromSecret(secret):
    return ''.join([k.capitalize() for k in sha256(secret.encode('UTF-8')).hexdigest()])[:32].replace('9','A').replace('8','B').replace('0','C').replace('1','D')

def getOTPObjectFromUserAttributes(user_email, user_created_on):
    return totp.TOTP(getOTPKeyFromSecret(user_email + user_created_on.strftime("%m%d%Y%H%M%S")))

def getOTPObjectFromUserId(user_id):
    user = User.query.filter_by(id = user_id).first()

    if not user:
        return False
    
    secret = user.email + user.created_on.strftime("%m%d%Y%H%M%S")

    return totp.TOTP(getOTPKeyFromSecret(secret))

def get_b64encoded_qr_image(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")

def getUpdatePortStatusSocket(port_ids = None):
    gameservers_obj = []

    all_gameservers_obj = getAvailablePortsFormated(None, True)

    if not port_ids:
        return all_gameservers_obj

    for gs in all_gameservers_obj:
        if gs.id in port_ids:
            gameservers_obj.append(gs)

    updateInteractivity(current_user)

    return gameservers_obj

def getUpdateLocalServerPorts(server, getMcStatus=False):
    gameservers_obj = []
    try:
        res = requests.get('http://' + server.ip + '/getMCServers', timeout=2)
        if res.status_code==200:
            res = res.json()
            for server_info in res.get('answer'):
                gameservers_dict = {}
                gameserver = Game_server.query.filter_by(server_id = server.id).filter_by(port = server_info['port']).first()

                mcstatus = 1

                if getMcStatus:
                    mcserver = JavaServer.lookup(server.ip+':'+str(server_info['port']))
                    
                    try:
                        stats = mcserver.status()
                        #desc.append(stats.description)
                        gameservers_dict['mc_ver'] = stats.version.name
                        gameservers_dict['players']= str(stats.players.online)+'/'+str(stats.players.max)

                        mcstatus = 0
                    except:
                        #desc.append('-')
                        gameservers_dict['mc_ver'] = '-'
                        gameservers_dict['players']= '-'

                        mcstatus = 1
                
                if not gameserver:
                    gameserver = Game_server(server_id = server.id, port = server_info['port'], updated_at = datetime.now(), status=mcstatus, include_schedule = True, correlation_id = server_info['findex'])
                    db.session.add(gameserver)
                else:
                    gameserver.updated_at = datetime.now()

                db.session.commit()

                gameservers_dict['is_local'] = True
                gameservers_dict['ip'] = server.public_ip
                gameservers_dict['local_port'] = server_info['port']
                gameservers_dict['port_status'] = mcstatus
                gameservers_dict['desc'] = server_info['name']
                gameservers_dict['dir'] = server_info['dir']
                gameservers_dict['id'] = gameserver.correlation_id
                gameservers_dict['info'] = gameserver.info_content

                gameservers_obj.append(gameservers_dict)

    except:
        print('Error fetching local servers')

    return gameservers_obj



def getAvailablePortsFormated(server_ip=None, getMcStatus=False):
    gameservers_obj = []

    servers = Server.query.filter_by(ip=server_ip).order_by(Server.id).all() if server_ip else Server.query.order_by(Server.id).all()
    
    for server in servers:
        if server.is_local:
            gameservers_obj = gameservers_obj + getUpdateLocalServerPorts(server, getMcStatus)
        else:
            game_servers = Game_server.query.filter_by(server_id = server.id).order_by(Game_server.id).all()
            for gs in game_servers:
                gameserver_dict = {}
                mcstatus = 1
                gameserver_dict['is_local'] = False
                gameserver_dict['ip'] = server.public_ip
                gameserver_dict['local_port'] = gs.port

                js = JavaServer.lookup(server.ip + ':' + str(gs.port))
                try:
                    js_status = js.status()
                    gameserver_dict['desc'] = js_status.motd.parsed[0]
                    if (getMcStatus):
                        gameserver_dict['mc_ver'] = js_status.version.name
                        gameserver_dict['players']= str(js_status.players.online)+'/'+str(js_status.players.max)
                        gs.status = 0
                        mcstatus = 0
                except:
                    gameserver_dict['desc'] = ''
                    if (getMcStatus):
                        gameserver_dict['mc_ver'] = '-'
                        gameserver_dict['players']= '-'
                        gs.status = 1
                        mcstatus = 1
                
                gameserver_dict['port_status'] = mcstatus
                gameserver_dict['dir'] = ''
                gameserver_dict['id'] = gs.correlation_id
                gameserver_dict['info'] = gs.info_content if gs.info_content else ''

                gs.updated_at = datetime.now()
                db.session.commit()
                
                gameservers_obj.append(gameserver_dict)
                

    #return ip, local_port, descs, port_status, dirs, len(port_status), ids, is_local
    for i in range(len(gameservers_obj)):
        gameservers_obj[i]['order_id'] = i+1

    return gameservers_obj

def getSSHPortFormated():
    try:
        res = requests.get('http://' + SERVER_IP + '/hello', timeout=1)
        
        return OFFICIAL_DOMAIN+':2255' if res.status_code==200 else 'Server Offline'
    except:
        return 'Server Offline'

def getAnnouncemnts():
    announcements = Announcements.query.order_by(desc(Announcements.created_on)).all()
    announcements_obj = []

    for announcement in announcements:
        announcement_dict = {}
        announcement_dict['username'] = announcement.created_by
        announcement_dict['uuid'] = announcement.created_by_uuid
        announcement_dict['date'] = getDatetimeFormatedNoSeconds(announcement.created_on)
        announcement_dict['text'] = announcement.content.replace('\n', '<br>')
        announcement_dict['id'] = announcement.id

        announcements_obj.append(announcement_dict)

    #return [usernames, uuids, dates, text, ids, len(usernames)]
    return announcements_obj

def updateInteractivity(user):
    user.last_login = datetime.now()
    db.session.commit()

def getAllUserData():
    users = User.query.order_by(desc(User.last_login)).all()
    users_obj = []
    usernames  = []
    dates = []
    uuids = []
    emails = []
    validated = []
    i=1

    for user in users:
        user_dict = {}
        user_dict['username'] = user.username
        user_dict['uuid'] = user.uuid
        user_dict['last_login'] = getDatetimeFormatedNoSeconds(user.last_login)
        user_dict['email'] = user.email
        user_dict['validated'] = 1 if user.is_authed else 0
        user_dict['order_id'] = i

        users_obj.append(user_dict)
        i += 1
    
    #return usernames, uuids, dates, emails, validated, len(usernames)
    return users_obj

def getServerStatus(ip):
    try:
        res = requests.get('http://'+ip+'/hello', timeout=1)
        server = Server.query.filter_by(ip=ip).first()

        if server:
            server.current_status = 'Online' if res.status_code==200 else 'Offline'
            db.session.commit()
        
        return 'Online' if res.status_code==200 else 'Offline'
    except:
        server = Server.query.filter_by(ip=ip).first()

        if server:
            server.current_status = 'Offline'
            db.session.commit()

        return 'Offline'

def getUpdateServers():
    servers = Server.query.order_by(Server.id).all()
    servers_obj = []
    i=1

    for server in servers:
        server_dict = {}

        server_dict['ip'] = server.ip
        server_dict['status'] = getServerStatus(server.ip)
        server_dict['is_local'] = 1 if server.is_local else 0
        server_dict['order_id'] = i

        servers_obj.append(server_dict)
        i+=1

    
    #print([ips, statuses, i, is_local])
    return servers_obj

def attempt_wol(ip):
    server = Server.query.filter_by(ip=ip).first()
    attempt = False
    if (server):
        status = Server_status.query.filter_by(server_id=server.id).filter_by(status='wol').order_by(desc(Server_status.time)).first()
        if (status):
            if ((datetime.now()-status.time).total_seconds()>300):
                attempt = True
        else:
            attempt = True

    if (attempt):
        os.system('etherwake -i eth0 ' + server.mac)
        new_status = Server_status(server_id = server.id,status='wol',time=datetime.now())
        db.session.add(new_status)
        db.session.commit()
    
    return attempt

def attempt_shutdown(ip):
    server = Server.query.filter_by(ip=ip).first()
    attempt = False
    if (server):
        status = Server_status.query.filter_by(server_id=server.id).filter_by(status='shutdown').order_by(desc(Server_status.time)).first()
        if (status):
            if ((datetime.now()-status.time).total_seconds()>300):
                try:
                    attempt = True
                except:
                    attempt = False

        else:
            attempt = True

    if (attempt):
        new_status = Server_status(server_id = server.id,status='shutdown',time=datetime.now())
        db.session.add(new_status)
        db.session.commit()
        try:
            requests.get('http://'+ip+'/shutdown_server')
        except:
            pass
    
    return attempt

def getJavaServers(ip):
    data = getAvailablePortsFormated(ip)

    for i in range(len(data)):
        server = Server.query.filter_by(public_ip=data[i]['ip']).first()
        if server:
            game_server = Game_server.query.filter_by(server_id=server.id).filter_by(port = data[i]['local_port']).first()
            if game_server:
                if game_server.include_schedule:
                    data[i]['schedule'] = 1
                else:
                    data[i]['schedule'] = 0
            else:
                data[i]['schedule'] = -1
        else:
            data[i]['schedule'] = -1

    return data

def toggleGameServerSchedule(ip, port):
    server = Server.query.filter_by(public_ip=ip).first()

    if server:
        game_server = Game_server.query.filter_by(server_id=server.id).filter_by(port=port).first()
        if game_server:
            game_server.include_schedule = not game_server.include_schedule
            db.session.commit()
            return True

    return False

def generateNewSSHKeyRebel():
    server = Server.query.first()

    if server:
        try:
            res = requests.post('http://' + server.ip + '/rebel_reset_key', timeout=10)
            if (res.status_code==200):
                resj =  res.json()
                if (resj.get('private_key')):
                    return resj.get('private_key')
             
        except:
            pass

    return '-1'

def generateRandomEmailOTP():
    return random_base32()[:8]