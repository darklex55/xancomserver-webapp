from flask_socketio import emit
import socketio
from .python_utils import getPortStatus, getAnnouncemnts
from .models import db, Announcements
from flask_login import current_user
from datetime import datetime

def run_sockets(socketio):
    @socketio.on('ask port status')
    def handle_message(data):
        status, status_len, desc, mc_ver, players, date_now = getPortStatus()
        emit('get port status', [status, status_len, desc, mc_ver, players, date_now])

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
    