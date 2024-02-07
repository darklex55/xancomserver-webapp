from flask import Blueprint, flash, render_template, request, session, redirect, url_for, make_response
from .python_utils import getCurrentDatetimeFormated, getAvailablePortsFormated, getAllUserData, updateInteractivity, getSSHPortFormated, produceHashFromText, getServers, attempt_wol, attempt_shutdown, getServerStatus, getJavaServers, toggleGameServerSchedule, generateNewSSHKeyRebel
from .email_utils import sendPrivateKey
from flask_login import login_required, current_user, logout_user
from .models import User, Announcements, Server, Game_server
from . import SERVER_IP, db

import requests

views = Blueprint('views', __name__)

@views.route('/')
@login_required
def home():
    session.clear()
    if current_user.uuid == '8667ba71b85a4004af54457a9734eed7':
        flash('Buy minecraft you filthy pirate.', category='error')
    updateInteractivity(current_user)
    ips, local_ports, descs, ports_status, dirs, ports_len, ids, is_local = getAvailablePortsFormated()
    usernames, uuids, userdates, __, __, userdata_len = getAllUserData()
    return render_template("home.html", dt = getCurrentDatetimeFormated(), ips=ips, local_ports = local_ports, descs=descs, ports_status = ports_status, ports_len = ports_len, usernames = usernames, userdates = userdates, uuids=uuids, userdata_len = userdata_len, ids=ids, is_local=is_local), 200

@views.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    updateInteractivity(current_user)
    ssh_ip = getSSHPortFormated()
    session.clear()
    if request.method=='POST':
        db.session.delete(current_user)
        db.session.commit()
        flash('User deleted successfuly', category='success')
        logout_user()
        return redirect(url_for('auth.login'))

    if 'msg' in request.args and 'category' in request.args:
        messages = {1: "WoL Package sent. Please refresh the page in a while to confirm the server's status.",
        2: "WoL has already been sent. Please wait.",
        3: 'Invalid Request.',
        4: "Shutdown Package sent. Please refresh the page in a while to confirm the server's status.",
        5: "Shutdown Package has already been sent. Please wait.",
        6: "Server appears to be offline.",
        11: "Host added to list",
        12: "Host already exists",
        13: "Host removed from list",
        14: "Host not found",
        21: "The new key has been shared to you via email. Any older key has been invalidated.",
        22: "Could not reset key - unexpected error."}
        flash(messages.get(int(request.args['msg'])), category=request.args['category'])


    return render_template("settings.html", dt = getCurrentDatetimeFormated(), ssh_ip = ssh_ip, servers = getServers())

@views.route('/user_management', methods=['GET', 'POST'])
@login_required
def user_management():
    if (current_user.is_authenticated):

        if request.method=='POST':
            user = User.query.filter_by(email=request.form.get('email')).first()
            if (user):
                u_mail = user.email
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfuly', category='success')
                if current_user.email == u_mail:
                    logout_user()
                    return redirect(url_for('auth.login'))


        username, __, logins, email, validated, length = getAllUserData()
        return render_template("user_management.html", dt = getCurrentDatetimeFormated(), user_obj=[username, email, validated, logins, length])

    return redirect(url_for('views.home'))

@views.route('/settings/turn_on', methods=['POST'])
@login_required
def turn_on():
    updateInteractivity(current_user)
    message = ''
    category = ''
    if current_user.is_privilleged:
        if 'ip' in request.form:
            attempt = attempt_wol(request.form['ip'])
            if attempt:
                message = 1
                category = 'success'
            else:
                message = 2
                category = 'error'
        else:
            message = 3
            category = 'error'
    else:
        message = 3
        category = 'error'

    return redirect(url_for('views.settings') + '?msg=' + str(message)+ '&category=' + category)

@views.route('/settings/add_unmanaged', methods=['POST'])
@login_required
def add_unmanaged():
    updateInteractivity(current_user)
    message = ''
    category = ''
    if current_user.is_privilleged:
        if 'server_ip' in request.form:
            if Server.query.filter_by(ip = request.form['server_ip']).first():
                message = 12
                category = 'error'
            else:
                new_server = Server(is_local=False, ip = request.form['server_ip'], public_ip = request.form['server_ip'], mac = None, current_status = None)
                db.session.add(new_server)
                db.session.commit()
                message = 11
                category = 'success'
        else:
            message = 3
            category = 'error'
    else:
        message = 3
        category = 'error'

    return redirect(url_for('views.settings') + '?msg=' + str(message)+ '&category=' + category)

@views.route('/settings/remove_unmanaged', methods=['POST'])
@login_required
def remove_unmanaged():
    updateInteractivity(current_user)
    message = ''
    category = ''
    if current_user.is_privilleged:
        if 'ip' in request.form:
            server = Server.query.filter_by(ip = request.form['ip']).first()
            if server and not server.is_local:
                game_servers = Game_server.query.filter_by(server_id = server.id).all()
                for gs in game_servers:
                    db.session.delete(gs)
            
                db.session.delete(server)
                db.session.commit()
                message = 13
                category = 'success'
            else:
                message = 14
                category = 'error'
        else:
            message = 3
            category = 'error'
    else:
        message = 3
        category = 'error'

    return redirect(url_for('views.settings') + '?msg=' + str(message)+ '&category=' + category)

@views.route('/manage', methods=['GET','POST'])
@login_required
def manage():
    updateInteractivity(current_user)
    if current_user.is_privilleged:
        if 'ip' in request.args:
            if (getServerStatus(request.args['ip'])):
                if ('msg' in request.args and 'category' in request.args):
                    messages= {1: 'Stop command send successfuly.',
                    2: 'Startup command send successfuly',
                    3: 'Error Contacting Server',
                    4: 'Wrong Request',
                    11: 'Gameserver added successfuly',
                    12: 'Error creating gameserver',
                    13: 'Gameserver removed successfuly',
                    14: 'Error removing gameserver'}

                    flash(messages[int(request.args['msg'])], category=request.args['category'])

                ips, ports, descs, statuses, dirs, lens, ids, is_local, schedules = getJavaServers(request.args['ip'])
                return render_template("manage.html", dt = getCurrentDatetimeFormated(), ips = ips, ports = ports, descs = descs, statuses=statuses, dirs=dirs, lens=lens, schedules=schedules, ids=ids, managed=any(is_local))
            else:
                return redirect(url_for('views.settings') + '?msg=6&category=error')
        else:
            return redirect(url_for('views.settings') + '?msg=3&category=error')
    else:
        return redirect(url_for('views.settings') + '?msg=3&category=error')

@views.route('/request_turnon', methods=['POST'])
@login_required
def request_turnon():
    updateInteractivity(current_user)
    if 'server_port' in request.args and 'server_ip' in request.form:
        server = Server.query.filter_by(public_ip = request.form['server_ip']).first()
        if server:
            try:
                res = requests.get('http://' + server.ip + '/getMCServers', timeout=2)
                if res.status_code==200:
                    res = res.json()
                    ports = res.get('answer')[1]
                    if request.args['server_port'] in ports:
                        try:
                            requests.get('http://'+ server.ip +'/run_mc_server?name='+res.get('answer')[2][ports.index(request.args['server_port'])], timeout=1)
                            flash('Server Start Request Submitted', 'success')
                            return redirect(url_for('views.home'))
                        except:
                            return redirect(url_for('views.home'))
                    else:
                        return redirect(url_for('views.home'))
                else:
                    return redirect(url_for('views.home'))

            except:
                return redirect(url_for('views.home'))
        else:
            return redirect(url_for('views.home'))
    else:
        return redirect(url_for('views.home'))

@views.route('/manage/toggle_schedule', methods=['POST'])
@login_required
def schedule_toggle():
    updateInteractivity(current_user)
    if current_user.is_privilleged:
        if 'ip' in request.args and 'port' in request.args:
            toggleGameServerSchedule(request.args['ip'],request.args['port'])
            return redirect(request.referrer.split('&')[0])
        else:
            return redirect(request.referrer.split('&')[0] + '&msg=4&category=error')
    else:
        return redirect(request.referrer.split('&')[0] + '&msg=4&category=error')

@views.route('/manage/shutoff', methods=['GET','POST'])
@login_required
def manage_shutoff():
    updateInteractivity(current_user)
    if current_user.is_privilleged:
        if 'name' in request.args and 'server_ip' in request.args:
            try:
                requests.get('http://'+request.args['server_ip']+'/shutoff_mc_server?name='+request.args['name'], timeout=1)
                return redirect(request.referrer.split('&')[0]+'&msg=1&category=success')
            except:
                return redirect(request.referrer.split('&')[0]+'&msg=3&category=error')
        else:
            return redirect(request.referrer.split('&')[0]+'&msg=4&category=error')
    else:
        return redirect(url_for('views.settings') + '?msg=3&category=error')

@views.route('/manage/turnon', methods=['GET','POST'])
@login_required
def manage_turnon():
    updateInteractivity(current_user)
    if current_user.is_privilleged:
        if 'name' in request.args and 'server_ip' in request.args:
            try:
                requests.get('http://'+request.args['server_ip']+'/run_mc_server?name='+request.args['name'], timeout=1)
                return redirect(request.referrer.split('&')[0]+'&msg=2&category=success')
            except:
                return redirect(request.referrer.split('&')[0]+'&msg=3&category=error')
        else:
            return redirect(request.referrer.split('&')[0]+'&msg=4&category=error')
    else:
        return redirect(url_for('views.settings') + '?msg=3&category=error')

@views.route('/settings/turn_off', methods=['POST'])
@login_required
def turn_off():
    updateInteractivity(current_user)
    message = ''
    category = ''
    if current_user.is_privilleged:
        if 'ip' in request.form:
            attempt = attempt_shutdown(request.form['ip'])
            if attempt:
                message = 4
                category = 'success'
            else:
                message = 5
                category = 'error'
        else:
            message = 3
            category = 'error'
    else:
        message = 3
        category = 'error'

    return redirect(url_for('views.settings') + '?msg=' + str(message)+ '&category=' + category)
    

@views.route('/manage/add_unmanaged_gameserver', methods=['POST'])
@login_required
def add_unmanaged_gameserver():
    updateInteractivity(current_user)
    if current_user.is_privilleged:
        if 'server_ip' in request.form and 'server_port' in request.form:
            server = Server.query.filter_by(ip = request.form['server_ip']).first()
            if server:
                if not Game_server.query.filter_by(server_id = server.id).filter_by(port = request.form['server_port']).first():
                    new_game_server = Game_server(server_id = server.id, port = request.form['server_port'], updated_at = None, include_schedule=False, status = None)
                    db.session.add(new_game_server)
                    db.session.commit()
                    return redirect(request.referrer.split('&')[0] + '&msg=11&category=success')
    else:
        return redirect(url_for('views.settings'))

    return redirect(request.referrer.split('&')[0] + '&msg=12&category=error')

@views.route('/manage/remove_unmanaged_gameserver', methods=['POST'])
@login_required
def remove_unmanaged_gameserver():
    updateInteractivity(current_user)
    if current_user.is_privilleged:
        if 'gameserver_ip' in request.form:
            ip = request.form['gameserver_ip'].split(':')[0]
            port = request.form['gameserver_ip'].split(':')[-1]
            server = Server.query.filter_by(ip = ip).first()
            if server and not server.is_local:
                game_servers = Game_server.query.filter_by(server_id = server.id).filter_by(port = port).first()
                if (game_servers):
                    db.session.delete(game_servers)
                    db.session.commit()
                    return redirect(request.referrer.split('&')[0] + '&msg=13&category=success')
    else:
        return redirect(url_for('views.settings'))

    return redirect(request.referrer.split('&')[0] + '&msg=14&category=error')

@views.route('/settings/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    updateInteractivity(current_user)
    if (request.method=='POST' and current_user.is_privilleged):
        print(user_id)
    return redirect(url_for('views.settings'))

@views.route('/delete_announcement')
@login_required
def delete_announcement():
    if current_user.is_privilleged:
        if 'announcement_id' in request.args:
            announcement = Announcements.query.filter_by(id=request.args['announcement_id']).first()
            if announcement:
                db.session.delete(announcement)
                db.session.commit()
        else:
            flash('Invalid Action', type='error')
    else:
        flash('Invalid Action', type='error')

    return redirect(url_for('views.home'))

@views.route('/manage/reset_ssh_key', methods=['POST'])
@login_required
def reset_ssh_key():
    message = 22
    category = 'error'

    if(current_user.is_privilleged):
        key = generateNewSSHKeyRebel()
        if (key != '-1'):
            sendPrivateKey(current_user.email, key)
            message = 21
            category = 'success'

    return redirect(url_for('views.settings') + '?msg=' + str(message)+ '&category=' + category)

@views.route('/verification')
def account_verification():
    session.clear()
    if 'auth_key' in request.args:
        user = User.query.filter_by(mail_auth_key=request.args['auth_key']).first()

        if user:
            user.is_authed = True
            user.auth_key = produceHashFromText(str(user.email) + str(user.password))
            db.session.commit()
            flash('Verification Completed Successfuly', category='success')
        else:
            flash('Verification Error', category='error')

    else:
        flash('Verification Error', category='error')
    return redirect(url_for('views.home'))