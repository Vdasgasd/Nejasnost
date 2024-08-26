from flask import Blueprint, render_template, url_for, flash, redirect, request, jsonify
from app import db, bcrypt
from app.models import User
from app.models import ChatID
from flask_login import login_user, current_user, logout_user, login_required

from flask import  render_template

main = Blueprint('main', __name__)

@main.route('/')

@main.route('/login', methods=['GET', 'POST'])

def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if user.password == password or bcrypt.check_password_hash(user.password, password) :
                login_user(user, remember=True)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
            else:
                flash('Login Unsuccessful. Please check email and password', 'danger')
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login')

@main.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.login'))



@main.route('/edit_account', methods=['GET', 'POST'])
@login_required
def edit_account():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not(current_user.password, old_password):
            flash('Old password is incorrect', 'danger')
        elif new_password != confirm_password:
            flash('New password and confirmation password do not match', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated', 'success')
            return redirect(url_for('main.dashboard'))
    return render_template('edit_account.html', title='Edit Account')

@main.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        chat_id = request.form.get('chat_id')
        chat_name = request.form.get('chat_name')
        if chat_id and chat_name:
            new_chat_id = ChatID(chat_id=chat_id, chat_name=chat_name)
            db.session.add(new_chat_id)
            db.session.commit()
            flash('Chat ID added successfully', 'success')
        else:
            flash('Chat ID and Chat Name cannot be empty', 'danger')

    chat_ids = ChatID.query.all()
    return render_template('dashboard.html', title='Dashboard', chat_ids=chat_ids)

@main.route('/delete_chat_id/<int:chat_id>', methods=['POST'])
@login_required
def delete_chat_id(chat_id):
    chat = ChatID.query.get_or_404(chat_id)
    db.session.delete(chat)
    db.session.commit()
    flash('Chat ID deleted successfully', 'success')
    return redirect(url_for('main.dashboard'))


@main.route('/api/chatid', methods=['GET'])
def get_chat_ids():
    chat_ids = ChatID.query.with_entities(ChatID.chat_id).all()
    return jsonify([chat_id[0] for chat_id in chat_ids])
