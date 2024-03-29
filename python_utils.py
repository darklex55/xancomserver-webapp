from datetime import datetime

from flask_login import current_user
from .models import User, db, Announcements, Server, Server_status, Game_server
from sqlalchemy import desc
from mcstatus import JavaServer
from hashlib import sha1, sha256

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

def getPortStatusSocket(server_ip = None):
    status = []
    desc = []
    mc_ver = []
    players = []
    details = []
    is_local = []
    ids = []

    servers = Server.query.filter_by(ip=server_ip).all() if server_ip else Server.query.all()

    for s in servers:
        if s.is_local:
            try:
                res = requests.get('http://' + s.ip + '/getMCServers', timeout=2)
                if res.status_code==200:
                    res = res.json()
                    ports = res.get('answer')[1]
                    i=0
                    for port in ports:
                        server = JavaServer.lookup(s.ip+':'+str(port))
                        result = 1
                        
                        try:
                            stats = server.status()
                            #desc.append(stats.description)
                            mc_ver.append(stats.version.name)
                            players.append(str(stats.players.online)+'/'+str(stats.players.max))

                            result = 0
                        except:
                            #desc.append('-')
                            mc_ver.append('-')
                            players.append('-')

                            result = 1

                        is_local.append(True)
                        ids.append(sha1(bytes(str(s.public_ip) + '..' + str(port), encoding='utf-8')).hexdigest())
                        desc.append(res.get('answer')[0][i])
                        i+=1
                        status.append(result)

            except:
                return [],[],0,[],[],0, [], getCurrentDatetimeFormated()
        else:
            game_servers = Game_server.query.filter_by(server_id = s.id)
            for gs in game_servers:
                server = JavaServer.lookup(s.ip+':'+str(gs.port))
                result = 1
                try:
                    stats = server.status()
                    mc_ver.append(stats.version.name)
                    players.append(str(stats.players.online)+'/'+str(stats.players.max))

                    result = 0
                except:
                    mc_ver.append('-')
                    players.append('-')

                    result = 1

                is_local.append(False)
                ids.append(sha1(bytes(str(s.public_ip) + '..' + str(gs.port), encoding='utf-8')).hexdigest())
                desc.append('')
                status.append(result)

    updateInteractivity(current_user)

    return ids, status, len(status), desc, mc_ver, players, is_local, getCurrentDatetimeFormated()

def getAvailablePortsFormated(server_ip=None):
    ip = []
    local_port = []
    port_status = []
    descs = []
    dirs = []
    ids = []
    is_local = []
    i=0

    servers = Server.query.filter_by(ip=server_ip).all() if server_ip else Server.query.all()
    
    for server in servers:
        if server.is_local:
            try:
                res = requests.get('http://' + server.ip + '/getMCServers', timeout=2)
                if res.status_code==200:
                    res = res.json()
                    print(res.get('answer'))
                    for port in res.get('answer')[1]:
                        is_local.append(True)
                        ip.append(server.public_ip)
                        local_port.append(port)
                        port_status.append(1)
                        descs.append(res.get('answer')[0][i])
                        dirs.append(res.get('answer')[2][i])
                        ids.append(sha1(bytes(str(server.public_ip) + '..' + str(port), encoding='utf-8')).hexdigest())
                        i+=1
            except:
                continue
        else:
            game_servers = Game_server.query.filter_by(server_id = server.id)
            for gs in game_servers:
                is_local.append(False)
                ip.append(server.public_ip)
                local_port.append(gs.port)
                port_status.append(1)
                js = JavaServer.lookup(server.ip + ':' + str(gs.port))
                try:
                    js_status = js.status()
                    print(js_status.motd.parsed[0])
                    descs.append(js_status.motd.parsed[0])
                except:
                    descs.append('')
                ids.append(sha1(bytes(str(server.public_ip) + '..' + str(gs.port), encoding='utf-8')).hexdigest())
                dirs.append('')
                

    return ip, local_port, descs, port_status, dirs, len(port_status), ids, is_local

def getSSHPortFormated():
    try:
        res = requests.get('http://' + SERVER_IP + '/hello', timeout=1)
        
        return OFFICIAL_DOMAIN+':2255' if res.status_code==200 else 'Server Offline'
    except:
        return 'Server Offline'

def getAnnouncemnts():
    announcements = Announcements.query.order_by(desc(Announcements.created_on)).all()
    usernames = []
    uuids = []
    dates = []
    text = []
    ids = []
    for announcement in announcements:
        usernames.append(announcement.created_by)
        uuids.append(announcement.created_by_uuid)
        dates.append(getDatetimeFormatedNoSeconds(announcement.created_on))
        content = announcement.content.replace('\n','<br>')
        text.append(content)
        ids.append(announcement.id)
    return [usernames, uuids, dates, text, ids, len(usernames)]

def updateInteractivity(user):
    user.last_login = datetime.now()
    db.session.commit()

def getAllUserData():
    users = User.query.order_by(desc(User.last_login)).all()
    usernames  = []
    dates = []
    uuids = []
    emails = []
    validated = []

    for user in users:
        usernames.append(user.username)
        uuids.append(user.uuid)
        dates.append(getDatetimeFormatedNoSeconds(user.last_login))
        emails.append(user.email)
        validated.append(1 if user.is_authed else 0)
    
    return usernames, uuids, dates, emails, validated, len(usernames)

def getServerStatus(ip):
    try:
        res = requests.get('http://'+ip+'/hello', timeout=1)
        return 'Online' if res.status_code==200 else 'Offline'
    except:
        return 'Offline'

def getServers():
    servers = Server.query.all()
    ips = []
    statuses = []
    is_local = []
    i=0

    for server in servers:
        ips.append(server.ip)
        current_status = getServerStatus(server.ip)
        server.current_status = current_status
        statuses.append(current_status)
        is_local.append(1 if server.is_local else 0)
        i+=1

    if (i>0):
        db.session.commit()
    
    print([ips, statuses, i, is_local])
    return [ips, statuses, i, is_local]

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
    schedules = []

    for i in range(len(data[0])):
        server = Server.query.filter_by(public_ip=data[0][i]).first()
        if server:
            game_server = Game_server.query.filter_by(server_id=server.id).filter_by(port = data[1][i]).first()
            if game_server:
                if game_server.include_schedule:
                    schedules.append(1)
                else:
                    schedules.append(0)
            else:
                schedules.append(-1)
        else:
            schedules.append(-1)

    data = data + (schedules,)

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