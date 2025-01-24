import requests
import sqlite3
from flask import g

# データベース設定
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('oauth_client.db')
    return g.db

# OAuth認証開始
auth_url = 'http://localhost:5000/oauth/authorize'
params = {
    'client_id': 'your_client_id',
    'redirect_uri': 'http://localhost:5001/callback'
}
print(f"Access: {auth_url}?client_id={params['client_id']}&redirect_uri={params['redirect_uri']}")

# コールバックで受け取ったコードでトークン取得
code = input("Enter the code from callback URL: ")
token_response = requests.post('http://localhost:5000/oauth/token', data={
    'code': code,
    'client_id': params['client_id']
})

# トークンでユーザー情報取得
token = token_response.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}
user_info = requests.get('http://localhost:5000/api/users/me', headers=headers).json()
print(user_info)