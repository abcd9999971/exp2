from flask import render_template, redirect, url_for, flash, request, jsonify, current_app
from urllib.parse import urlsplit
from flask_login import login_user, logout_user, current_user, login_required
from flask_babel import _
import sqlalchemy as sa
from datetime import datetime, timedelta, timezone
import secrets
from app import db
from app.auth import bp
from app.auth.forms import LoginForm, RegistrationForm, \
    ResetPasswordRequestForm, ResetPasswordForm, DeviceAuthForm
from app.models import User, DeviceCode, AuthorizationCode
from app.auth.email import send_password_reset_email


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            flash(_('Invalid username or password'))
            return redirect(url_for('auth.login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    return render_template('auth/login.html', title=_('Sign In'), form=form)


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(_('Congratulations, you are now a registered user!'))
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', title=_('Register'),
                           form=form)


@bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.email == form.email.data))
        if user:
            send_password_reset_email(user)
        flash(
            _('Check your email for the instructions to reset your password'))
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password_request.html',
                           title=_('Reset Password'), form=form)


@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash(_('Your password has been reset.'))
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)

@bp.route('/oauth/device/code', methods=['POST'])
def device_code():
    """デバイスコードを発行するエンドポイント"""
    client_id = request.form.get('client_id')
    if not client_id == current_app.config['OAUTH_CLIENT_ID']:
        return jsonify({'error': 'invalid_client'}), 400

    device_code = secrets.token_urlsafe(32)
    user_code = secrets.token_urlsafe(8).upper()[:8]  # 8文字の大文字コード
    
    device = DeviceCode(
        device_code=device_code,
        user_code=user_code
    )
    db.session.add(device)
    db.session.commit()

    return jsonify({
        'device_code': device_code,
        'user_code': user_code,
        'verification_uri': url_for('auth.verify_device', _external=True),
        'expires_in': 600,  # 10分
        'interval': 5
    })

@bp.route('/oauth/verify', methods=['GET', 'POST'])
@login_required
def verify_device():
    """ユーザーがデバイスコードを確認するエンドポイント"""
    form = DeviceAuthForm()
    if form.validate_on_submit():
        device = db.session.scalar(
            sa.select(DeviceCode).where(
                sa.and_(
                    DeviceCode.user_code == form.user_code.data.upper(),
                    DeviceCode.expires_at > datetime.utcnow(),
                    DeviceCode.user_id.is_(None)
                )
            )
        )
        
        if device:
            device.user_id = current_user.id
            db.session.commit()
            flash(_('Device has been authorized.'))
            return redirect(url_for('main.index'))
        else:
            flash(_('Invalid or expired code.'))
            
    return render_template('auth/verify_device.html',
                         title=_('Verify Device'),
                         form=form)

@bp.route('/oauth/token', methods=['POST'])
def token():
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'urn:ietf:params:oauth:grant-type:device_code':
        return handle_device_token()
    elif grant_type == 'authorization_code':
        return handle_auth_code_token()
    
    return jsonify({'error': 'unsupported_grant_type'}), 400

def handle_device_token():
    device_code = request.form.get('device_code')
    device = db.session.scalar(
        sa.select(DeviceCode).where(
            sa.and_(
                DeviceCode.device_code == device_code,
                DeviceCode.expires_at > datetime.utcnow()
            )
        )
    )

    if not device:
        return jsonify({'error': 'invalid_grant'}), 400

    if device.user_id is None:
        return jsonify({'error': 'authorization_pending'}), 400

    # 既存のget_tokenメソッドを使用
    user = db.session.get(User, device.user_id)
    token = user.get_token(expires_in=3600)  # 1時間
    
    # デバイスコードを削除（使い捨て）
    db.session.delete(device)
    db.session.commit()

    return jsonify({
        'access_token': token,
        'token_type': 'Bearer',
        'expires_in': 3600
    })

def handle_auth_code_token():
    code = request.form.get('code')
    client_id = request.form.get('client_id')
    
    auth_code = db.session.scalar(
        sa.select(AuthorizationCode).where(
            sa.and_(
                AuthorizationCode.code == code,
                AuthorizationCode.client_id == client_id,
                AuthorizationCode.expires_at > datetime.now(timezone.utc)
            )
        )
    )
    
    if not auth_code:
        return jsonify({'error': 'invalid_grant'}), 400
        
    user = auth_code.user
    token = user.get_token()
    
    db.session.delete(auth_code)
    db.session.commit()
    
    return jsonify({
        'access_token': token,
        'token_type': 'Bearer',
        'expires_in': 3600
    })

@bp.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    
    if request.method == 'GET':
        return render_template('auth/authorize.html',
                             client_id=client_id,
                             redirect_uri=redirect_uri)
    
    code = secrets.token_urlsafe(32)
    auth_code = AuthorizationCode(
        code=code,
        client_id=client_id,
        user_id=current_user.id,
        redirect_uri=redirect_uri
    )
    db.session.add(auth_code)
    db.session.commit()
    
    return redirect(f"{redirect_uri}?code={code}")
    
@bp.route('/oauth_callback')
def oauth_callback():
    code = request.args.get('code')
    access_token = request.args.get('access_token')

    if code:
        auth_code = AuthorizationCode.query.filter_by(code=code).first()
        if not auth_code:
            return 'Invalid code', 400
        
        user = auth_code.user
        token = user.get_token()
        
        db.session.delete(auth_code)
        db.session.commit()
        
        return render_template('oauth_callback.html', user=user)
    
    elif access_token:
        user = User.query.filter_by(token=access_token).first()
        if not user:
            return 'Invalid token', 400
        
        return render_template('oauth_callback.html', user=user)
    
    return 'Authorization failed', 400