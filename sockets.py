from flask_socketio import emit
import socketio
from .python_utils import getPortStatusSocket, getAnnouncemnts
from .models import db, Announcements
from flask_login import current_user
import json
from datetime import datetime

def run_sockets(socketio):
    @socketio.on('ask port status')
    def handle_message(data):
        server_ip = data.get('data', None)
        ids, status, status_len, desc, mc_ver, players, date_now = getPortStatusSocket(server_ip)
        emit('get port status', json.dumps({"ids": ids, "status": status, "status_len": status_len, 
                                        "desc": desc, "mc_ver": mc_ver, "players": players, "date_now": date_now}))

    @socketio.on('get_announcements')
    def handle_saved_announcements(data):
        announcement_data = getAnnouncemnts()
        emit('recieve_announcements', announcement_data)
    
    @socketio.on('send_announcement')
    def handle_announcement(data):
        if (current_user.is_privilleged):
            new_announcement = Announcements(created_by=current_user.username, created_by_uuid=current_user.uuid, created_on=datetime.today(), content=data['data'])
            db.session.add(new_announcement)
            db.session.commit()
            announcement_data = getAnnouncemnts()
            emit('recieve_announcements', announcement_data)
    