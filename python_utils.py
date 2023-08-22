from datetime import datetime

from flask_login import current_user
from .models import User, db, Announcements, Server, Server_status, Game_server
from sqlalchemy import desc
from mcstatus import MinecraftServer
from hashlib import sha256

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
import os

from urllib.parse import quote

from . import SERVER_IP, OFFICIAL_IP


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

def getPortStatus():
    status = []
    desc = []
    mc_ver = []
    players = []

    servers = Server.query.all()

    for s in servers:
        if s.is_local:
            try:
                res = requests.get('http://' + s.ip + '/getMCServers', timeout=2)
                if res.status_code==200:
                    res = res.json()
                    ports = res.get('answer')[1]
                    i=0
                    for port in ports:
                        server = MinecraftServer.lookup(s.ip+':'+str(port))
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

                        desc.append(res.get('answer')[0][i])
                        i+=1
                        status.append(result)

            except:
                return [],0,[],[],0, getCurrentDatetimeFormated()
        else:
            server = MinecraftServer.lookup(s.public_ip)
            result = 1
            try:
                stats = server.status()
                mc_ver.append(stats.version.name)
                players.append(str(stats.players.online)+'/'+str(stats.players.max))
                desc.append(stats.description)
                result = 0
            except:
                desc.append('-')
                mc_ver.append('-')
                players.append('-')

                result = 1
            
            i+=1    
            status.append(result)

    updateInteractivity(current_user)
                
    return status, len(status), desc, mc_ver, players, getCurrentDatetimeFormated()

def getAvailablePortsFormated():
    ip = []
    local_port = []
    port_status = []
    descs = []
    dirs = []
    i=0

    servers = Server.query.all()
    
    for server in servers:
        if server.is_local:
            try:
                res = requests.get('http://' + server.ip + '/getMCServers', timeout=2)
                if res.status_code==200:
                    res = res.json()
                    print(res.get('answer'))
                    for port in res.get('answer')[1]:
                        ip.append(server.public_ip)
                        local_port.append(port)
                        port_status.append(1)
                        descs.append(res.get('answer')[0][i])
                        dirs.append(res.get('answer')[2][i])
                        i+=1
            except:
                continue
        else:
            ip.append(':'.join(server.public_ip.split(':')[:-1]))
            local_port.append(server.split(':')[-1])
            port_status.append(1)
            descs.append('-')
            dirs.append('-')
            i+=1

    return ip, local_port, descs, port_status, dirs, len(port_status)

def getSSHPortFormated():
    try:
        res = requests.get('http://' + SERVER_IP + '/hello', timeout=1)
        
        return OFFICIAL_IP+':2255' if res.status_code==200 else 'Server Offline'
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

def sendValidationEmail(email, auth_key, url_root):
    msg = MIMEMultipart()
    msg['Subject'] = 'Xancomserver Account Verification'
    msg['From'] = 'darklex55server@gmail.com'
    text = 'Please validate your account by clicking the following link: http://'+ url_root +'/verification?auth_key='+ auth_key
    msg.attach(MIMEText(text,'plain'))
    smtp = smtplib.SMTP('smtp.gmail.com:587')
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.login('darklex55server@gmail.com','qpvfntgdvddadhqo')
    smtp.sendmail('darklex55server@gmail.com',email,msg.as_string())
    smtp.quit()

def sendPasswordResetEmail(email, auth_key, url_root):
    msg = MIMEMultipart()
    msg['Subject'] = 'Xancomserver Account Password Reset'
    msg['From'] = 'darklex55server@gmail.com'
    text = 'If you did not request for a new password, you can ignore this email. You can reset your password by following this link: http://'+ url_root +'/reset_password?auth_key='+ auth_key
    msg.attach(MIMEText(text,'plain'))
    smtp = smtplib.SMTP('smtp.gmail.com:587')
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.login('darklex55server@gmail.com','qpvfntgdvddadhqo')
    smtp.sendmail('darklex55server@gmail.com',email,msg.as_string())
    smtp.quit()

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
    i=0

    for server in servers:
        if server.is_local:
            ips.append(server.ip)
            current_status = getServerStatus(server.ip)
            server.current_status = current_status
            statuses.append(current_status)
            i+=1

    if (i>0):
        db.session.commit()
    
    return [ips, statuses, i]

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

def getMinecraftServers(ip):
    data = getAvailablePortsFormated()
    print(data)
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
