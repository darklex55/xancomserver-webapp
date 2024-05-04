from collections import UserList
from flask import Blueprint, make_response, render_template, request, redirect, url_for, flash, session
import requests
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, OFFICIAL_DOMAIN
from flask_login import login_user, login_required, logout_user, current_user
from datetime import datetime
from .python_utils import produceHashFromText, getOTPObjectFromUserId, getOTPObjectFromUserAttributes, get_b64encoded_qr_image, generateRandomEmailOTP
from .email_utils import sendValidationEmail, sendPasswordResetEmail, sendOTPEmail
from random import random

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if (current_user.is_authenticated):
        return redirect(url_for('views.home'))

    if (request.method=='POST'):
        if (request.form.get('userName')):
            username = request.form.get('userName')
        else:
            username = session['userName']

        password = request.form.get('password')
        should_login = False

        user = User.query.filter_by(username=username).first()

        if session.get('passwordCheckPass', False):
            if request.form.get('one_step_back') or (session.get('mfa_type', None)=='A' and not session.get('userId', None)) or (session.get('mfa_type', None)=='M' and not session.get('mail_otp_key', None)):
                session['passwordCheckPass'] = False
            else:
                otp_obj = getOTPObjectFromUserId(session['userId'])
                if session.get('mfa_type', None) == 'A':
                    if request.form.get('otp_code'):
                        if otp_obj.verify(request.form.get('otp_code'), valid_window=1):
                            should_login = True
                        else:
                            flash('Wrong OTP code', category="error")
                    else:
                        flash('Wrong OTP code', category="error")
                else:
                    if request.form.get('otp_code') == session['mail_otp_key']:
                        should_login = True
                    else:
                        flash('Wrong OTP code', category="error")
        else:      
            session['passwordCheckPass'] = False
            if user:
                if not user.is_authed:
                    flash('Verify your account with the activation link you recieved on your email.', category='error')
                else:
                    if check_password_hash(user.password, password):
                        session['passwordCheckPass'] = True
                        session['userId'] = user.id
                        session['userName'] = user.username
                        session['mfa_type'] = user.mfa_type

                        if user.mfa_type == 'M':
                            session['mail_otp_key'] = generateRandomEmailOTP()
                            sendOTPEmail(user.email, session['mail_otp_key'])

                    else: 
                        flash('Incorrect login', category='error')
            else: 
                flash('Incorrect login', category='error')

        if should_login:
            user = User.query.filter_by(username=session['userName']).first()
            print('LOGIN')
            user.last_login = datetime.today()
            db.session.commit()
            flash('Logged in successfully', category='success')
            login_user(user, remember=True)
            #session.clear()
            return redirect(url_for('views.home'))


    return render_template("login.html", passwordCheckPass = session.get('passwordCheckPass', False), mfa_type = session.get('mfa_type', None))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfuly', category='success')
    return redirect(url_for('auth.login'))

@auth.route('/add_mfa', methods=['GET', 'POST'])
@login_required
def add_mfa():
    user = User.query.filter_by(username = current_user.username).first()
    otp_setup_img = None

    if user:
        if user.mfa_type=='A':
            return redirect(url_for('views.home'))
        if request.method=='POST':
            if request.form.get('otp_code'):
                otp_obj = getOTPObjectFromUserAttributes(user.email, user.created_on)
                if otp_obj.verify(request.form.get('otp_code'), valid_window=1):
                    user.mfa_type = 'A'
                    db.session.commit()
                    flash('Authenticator app added as MFA')
                    return redirect(url_for('views.home'))
                else:
                    otp_setup_img = get_b64encoded_qr_image(otp_obj.provisioning_uri(name=user.email, issuer_name='Xancom'))
                    flash('Wrong code - please try again', category='error')

        else:
            otp_obj = getOTPObjectFromUserAttributes(user.email, user.created_on)
            otp_setup_img = get_b64encoded_qr_image(otp_obj.provisioning_uri(name=user.email, issuer_name='Xancom'))
    else:
        return redirect(url_for('views.home'))

    return render_template("mfa_setup.html", otp_setup_img = otp_setup_img)

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method=='GET':
        session.clear()

    if (current_user.is_authenticated):
        return redirect(url_for('views.home'))

    if 'username' not in session:
        session['register_state'] = 0

    execute_registration = False
    otp_setup_img = None

    if (request.method=='POST'):
        if not request.form.get('one_step_back'):
            if session['register_state'] == 1:
                password1 = request.form.get('password1')
                password2 = request.form.get('password2')
                email = request.form.get('e_mail')

                if password1 != password2:
                    flash('Passwords don\'t match.', category='error')
                elif len(password1) < 7:
                    flash('Password must be at least 7 characters.', category='error')
                elif User.query.filter_by(email=email).first():
                    flash('Email already exists', category='error')
                else:
                    session['user_password_temp'] = generate_password_hash(password1, method='pbkdf2')
                    session['user_email_temp'] = email
                    session['user_registration_datetime'] = datetime.now()
                    session['register_state'] = 2
                
            elif (session['register_state'] == 2):
                if not request.form.get('getotpapp') and request.form.get('getotpmail'):
                    session['mfa_type'] = 'M'
                    execute_registration = True
                else:
                    otp_obj = getOTPObjectFromUserAttributes(session['user_email_temp'], session['user_registration_datetime'])
                    otp_setup_img = get_b64encoded_qr_image(otp_obj.provisioning_uri(name=session['user_email_temp'], issuer_name='Xancom'))
                    print(otp_obj.provisioning_uri(name=session['user_email_temp'], issuer_name='Xancom'))
                    print(otp_setup_img)

                session['register_state'] = 3
                
            elif (session['register_state'] == 3):
                session['mfa_type'] = 'A'
                otp_obj = getOTPObjectFromUserAttributes(session['user_email_temp'], session['user_registration_datetime'])
                otp_setup_img = get_b64encoded_qr_image(otp_obj.provisioning_uri(name=session['user_email_temp'], issuer_name='Xancom'))

                if request.form.get('otp_code'):
                    if otp_obj.verify(request.form.get('otp_code'), valid_window=1):
                        execute_registration = True
                    else:
                        flash('Wrong code - please try again', category='error')

            else:
                print(request.form)
                username = request.form.get('userName')

                if (username):
                    user = User.query.filter_by(username=username).first()
                    
                    if (user):
                        flash('User already exists', category='error')
                    else:
                        data = requests.get('https://api.mojang.com/users/profiles/minecraft/'+username)

                        if (data.status_code==200):
                            session['username'] = username
                            session['uuid'] = data.json().get('id')
                            session['register_state'] = 1
                        else:
                            session['username'] = username
                            session['uuid'] = '8667ba71b85a4004af54457a9734eed7'
                            session['register_state'] = 1
                            flash('Username is not a real minecraft username. You filthy pirate. Move along...', category='error')
        else:
            session['register_state'] = session['register_state'] - 1

    if execute_registration:
        #Register execution:
        new_user = User(username=session['username'], uuid=session['uuid'], password=session['user_password_temp'], is_privilleged = False, email=session['user_email_temp'], created_on=session['user_registration_datetime'], mfa_type=session['mfa_type'])
        db.session.add(new_user)
        db.session.commit()

        user = User.query.filter_by(email=session['user_email_temp']).first()
        user.mail_auth_key = produceHashFromText(str(user.id))
        db.session.commit()

        sendValidationEmail(session['user_email_temp'], produceHashFromText(str(user.id)), OFFICIAL_DOMAIN)

        #login_user(new_user, remember=True)
        session.clear()
        flash('Account created. Check your email for verification link (check Spam folder as well).', category='success')
        return redirect(url_for('auth.login'))

    resp = make_response(render_template("sign_up.html", state = session['register_state'], otp_setup_img = otp_setup_img, error_username=False))

    return resp

@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method=='GET':
        session.clear()

    if (current_user.is_authenticated):
        return redirect(url_for('views.home'))

    if 'username' not in session:
        session['username_check'] = False

    if (request.method=='POST'):
        if session['username_check']:
            email = request.form.get('e_mail')

            user = User.query.filter_by(email=email).first()

            if user:
                user.auth_key = produceHashFromText(str(user.email) + str(user.password) + str(random()))
                db.session.commit()
                sendPasswordResetEmail(email, user.auth_key, OFFICIAL_DOMAIN)

            session.clear()
            flash('If the details provided were correct, check your email for the next steps (check Spam folder as well).', category='success')
            return redirect(url_for('auth.login'))
        
        else:
            print(request.form)
            username = request.form.get('userName')

            if (username):
                user = User.query.filter_by(username=username).first()
                
                if (user):
                    session['username'] = username
                    session['username_check'] = True
                else:
                    flash('User does not exist', category='error')

        
    resp = make_response(render_template("forgot_password.html", boolean = session['username_check'], error_username=False))

    return resp

@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    session.clear()
    if request.method=='GET':
        if 'auth_key' in request.args:
            user = User.query.filter_by(auth_key=request.args['auth_key']).first()

            if user:
                return make_response(render_template("reset_password.html"))
            else:
                flash('Invalid Resource', category='error')
        else:
            flash('Invalid Resource', category='error')

        return redirect(url_for('views.home'))
    
    else:
        if 'auth_key' in request.args:
            user = User.query.filter_by(auth_key=request.args['auth_key']).first()
            if user:
                password1 = request.form.get('password1')
                password2 = request.form.get('password2')
                email = request.form.get('e_mail')

                if password1 != password2:
                    flash('Passwords don\'t match.', category='error')
                    return make_response(render_template("reset_password.html"))
                elif len(password1) < 7:
                    flash('Password must be at least 7 characters.', category='error')
                    return make_response(render_template("reset_password.html"))
                elif check_password_hash(user.password, password1):
                    flash('You cannot use the same password as you had before. Please change your password.', category='error')
                    return make_response(render_template("reset_password.html"))
                else:
                    user.password=generate_password_hash(password1, method='pbkdf2')
                    user.auth_key = produceHashFromText(str(user.email) + str(user.password) + str(random()))
                    db.session.commit()
                    flash("New password set successfuly!", category='success')
                    return redirect(url_for('views.home'))

            else:
                flash('Invalid Resource', category='error')
        else:
            flash('Invalid Resource', category='error')
        
        return redirect(url_for('views.home'))