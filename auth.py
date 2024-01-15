from collections import UserList
from flask import Blueprint, make_response, render_template, request, redirect, url_for, flash, session
import requests
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, OFFICIAL_DOMAIN
from flask_login import login_user, login_required, logout_user, current_user
from datetime import datetime
from .python_utils import produceHashFromText
from .email_utils import sendValidationEmail, sendPasswordResetEmail
from random import random

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if (current_user.is_authenticated):
        return redirect(url_for('views.home'))

    if (request.method=='POST'):
        username = request.form.get('userName')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        
        if user:
            if not user.is_authed:
                flash('Verify your account with the activation link you recieved on your email.', category='error')
            else:
                if check_password_hash(user.password, password):
                    user.last_login = datetime.today()
                    db.session.commit()
                    flash('Logged in successfully', category='success')
                    login_user(user, remember=True)
                    return redirect(url_for('views.home'))
                else: 
                    flash('Incorrect login', category='error')
        else: 
            flash('Incorrect login', category='error')


    return render_template("login.html")

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfuly', category='success')
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method=='GET':
        session.clear()

    if (current_user.is_authenticated):
        return redirect(url_for('views.home'))

    if 'username' not in session:
        session['username_check'] = False

    if (request.method=='POST'):
        if session['username_check']:
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
                is_privilleged = True if session['username'] in ['darklex', 'iolkos'] else False
                new_user = User(username=session['username'], uuid=session['uuid'], password=generate_password_hash(password1, method='sha256'), is_privilleged = is_privilleged, email=email)
                db.session.add(new_user)
                db.session.commit()

                user = User.query.filter_by(email=email).first()
                user.mail_auth_key = produceHashFromText(str(user.id))
                db.session.commit()

                sendValidationEmail(email, produceHashFromText(str(user.id)), OFFICIAL_DOMAIN)

                #login_user(new_user, remember=True)
                session.clear()
                flash('Account created. Check your email for verification link (check Spam folder as well).', category='success')
                return redirect(url_for('auth.login'))
        
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
                        session['username_check'] = True
                    else:
                        session['username'] = username
                        session['uuid'] = '8667ba71b85a4004af54457a9734eed7'
                        session['username_check'] = True
                        flash('Username is not a real minecraft username. You filthy pirate. Move along...', category='error')



        
    resp = make_response(render_template("sign_up.html", boolean = session['username_check'], error_username=False))

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
                    user.password=generate_password_hash(password1, method='sha256')
                    user.auth_key = produceHashFromText(str(user.email) + str(user.password) + str(random()))
                    db.session.commit()
                    flash("New password set successfuly!", category='success')
                    return redirect(url_for('views.home'))

            else:
                flash('Invalid Resource', category='error')
        else:
            flash('Invalid Resource', category='error')
        
        return redirect(url_for('views.home'))