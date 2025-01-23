import secrets
from flask import Blueprint, request, jsonify, render_template, redirect, current_app
from functools import wraps
from app.models import User, Client, AuthCode, Token
from app import db
import time
from flask_login import current_user

oauth_bp = Blueprint('oauth', __name__)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization')
        if not auth:
            return jsonify({'error': 'No token'}), 401
        token = auth.split(' ')[1]
        token_obj = Token.query.filter_by(access_token=token).first()
        if not token_obj or token_obj.expires < int(time.time()):
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

@oauth_bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        client = Client.query.filter_by(client_id=request.args.get('client_id')).first()
        if not client or client.redirect_uri != request.args.get('redirect_uri'):
            return 'Invalid client', 400
        return render_template('oauth/authorize.html',
                             client_id=client.client_id,
                             redirect_uri=client.redirect_uri)
    
    if request.form.get('confirm') == 'yes':
        code = secrets.token_urlsafe(32)
        auth_code = AuthCode(
            code=code,
            client_id=request.form.get('client_id'),
            user_id=current_user.id,
            expires=int(time.time()) + 600
        )
        db.session.add(auth_code)
        db.session.commit()
        return redirect(f"{request.form.get('redirect_uri')}?code={code}")
    
    return redirect(request.form.get('redirect_uri'))

@oauth_bp.route('/oauth/token', methods=['POST'])
def token():
    client = Client.query.filter_by(
        client_id=request.form.get('client_id'),
        client_secret=request.form.get('client_secret')
    ).first()
    
    if not client:
        return jsonify({'error': 'Invalid client'}), 401
        
    auth_code = AuthCode.query.filter_by(
        code=request.form.get('code'),
        client_id=client.client_id
    ).first()
    
    if not auth_code or auth_code.expires < int(time.time()):
        return jsonify({'error': 'Invalid code'}), 401
        
    access_token = secrets.token_urlsafe(32)
    token = Token(
        access_token=access_token,
        user_id=auth_code.user_id,
        client_id=client.client_id,
        expires=int(time.time()) + 3600
    )
    
    db.session.delete(auth_code)
    db.session.add(token)
    db.session.commit()
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': 3600
    })

@oauth_bp.route('/api/userinfo')
@require_auth
def userinfo():
    token = request.headers.get('Authorization').split(' ')[1]
    token_obj = Token.query.filter_by(access_token=token).first()
    user = User.query.get(token_obj.user_id)
    return jsonify({
        'username': user.username,
        'email': user.email,
        'about_me': user.about_me
    })