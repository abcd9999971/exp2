#!/usr/bin/env python3
import os
import sys
import time
import json
import requests
from urllib.parse import urljoin
import click

class MicroblogClient:
    def __init__(self):
        self.config = {
            'api_base_url': 'http://localhost:5000',
            'client_id': 'test-client'
        }
        self.token_file = os.path.expanduser('~/.microblog-token.json')
        self.access_token = None
        self.load_token()

    def load_token(self):
        """保存されているトークンを読み込む"""
        try:
            with open(self.token_file) as f:
                data = json.load(f)
                self.access_token = data.get('access_token')
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save_token(self, token_data):
        """トークンを保存する"""
        print("Saving token:", token_data)  # test
        with open(self.token_file, 'w') as f:
            json.dump(token_data, f)
        self.access_token = token_data['access_token']

    def get_headers(self):
        """APIリクエスト用のヘッダーを取得"""
        return {
            'Authorization': f'Bearer {self.access_token}',
            'Accept': 'application/json',
        }

    def device_auth_flow(self):
        """Device Authorization Grantフローを実行"""
        response = requests.post(
            urljoin(self.config['api_base_url'], '/auth/oauth/device/code'),
            data={'client_id': self.config['client_id']}
        )
        if response.status_code != 200:
            click.echo('デバイスコードの取得に失敗しました', err=True)
            return False

        auth_data = response.json()
        device_code = auth_data['device_code']
        user_code = auth_data['user_code']
        verification_uri = auth_data['verification_uri']
        interval = auth_data.get('interval', 5)

        click.echo('ブラウザで以下のURLを開き、表示されたコードを入力してください：')
        click.echo(f'URL: {verification_uri}')
        click.echo(f'コード: {user_code}')
        click.echo('認証待機中...')

        while True:
            time.sleep(interval)
            response = requests.post(
                urljoin(self.config['api_base_url'], '/auth/oauth/token'),
                data={
                    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                    'device_code': device_code,
                    'client_id': self.config['client_id']
                }
            )

            if response.status_code == 200:
                token_data = response.json()
                self.save_token(token_data)
                click.echo('認証が完了しました')
                return True
            elif response.status_code == 400:
                error = response.json().get('error')
                if error == 'authorization_pending':
                    click.echo('.', nl=False)
                    continue
                elif error == 'expired_token':
                    click.echo('\n認証の有効期限が切れました', err=True)
                    return False
                else:
                    click.echo(f'\nエラー: {error}', err=True)
                    return False
            else:
                click.echo('\n認証に失敗しました', err=True)
                return False

    def ensure_authenticated(self):
        """認証が必要な場合は認証フローを実行"""
        if not self.access_token or not self.verify_token():
            print("Token is invalid or not present. Initiating authentication flow.")
            if not self.device_auth_flow():
                sys.exit(1)

    def verify_token(self):
        """トークンの有効性を確認"""
        if not self.access_token:
            return False
        
        try:
            response = requests.get(
                urljoin(self.config['api_base_url'], '/api/verify_token'),
                headers=self.get_headers()
            )
            
            # test
            print(f"Token verification status: {response.status_code}")
            print(f"Token verification response: {response.text}")
            
            return response.status_code == 200
        except Exception as e:
            print(f"Token verification error: {e}")
            return False

    def get_about_me(self):
        """ユーザーのabout_me情報を取得"""
        self.ensure_authenticated()
        
        response = requests.get(
            urljoin(self.config['api_base_url'], '/api/users/me'),  
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        if response.status_code == 200:
            data = response.json()
            click.echo(f"ユーザー: {data['username']}")
            click.echo(f"About me: {data.get('about_me', '未設定')}")
            if 'last_seen' in data:
                click.echo(f"Last seen: {data['last_seen']}")
        else:
            click.echo('プロフィール情報の取得に失敗しました', err=True)
            sys.exit(1)

    def update_about_me(self, new_text):
        """ユーザーのabout_me情報を更新"""
        self.ensure_authenticated()
        
        response = requests.put(
            urljoin(self.config['api_base_url'], '/api/users/about_me'),  
            headers=self.get_headers(),
            json={'about_me': new_text}
        )
        
        if response.status_code == 200:
            click.echo('プロフィールを更新しました')
        else:
            click.echo('プロフィールの更新に失敗しました', err=True)
            sys.exit(1)

@click.group()
def cli():
    """Microblog CLI クライアント"""
    pass

@cli.command()
def about():
    """about_meを表示"""
    client = MicroblogClient()
    client.get_about_me()

@cli.command()
@click.argument('text')
def update(text):
    """about_meを更新"""
    client = MicroblogClient()
    client.update_about_me(text)

if __name__ == '__main__':
    cli()