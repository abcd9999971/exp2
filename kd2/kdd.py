import http.server
import urllib.parse
import secrets
import socketserver
import webbrowser

class OAuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        
        # OAuth授權請求
        if parsed_path.path == '/oauth/authorize':
            # 解析查詢參數
            query_params = dict(urllib.parse.parse_qsl(parsed_path.query))
            
            # 生成授權碼
            authorization_code = secrets.token_urlsafe(16)
            
            # 構建回調URL
            redirect_uri = query_params.get('redirect_uri', '')
            callback_url = f"{redirect_uri}?code={authorization_code}"
            
            # 發送重定向響應
            self.send_response(302)
            self.send_header('Location', callback_url)
            self.end_headers()
        
        else:
            # 處理其他路由
            super().do_GET()

def run_server(port=4000):
    with socketserver.TCPServer(("", port), OAuthHandler) as httpd:
        print(f"服務器運行在 http://localhost:{port}")
        # 自動打開瀏覽器測試
        webbrowser.open(f"http://localhost:{port}/oauth/authorize?client_id=test-client&redirect_uri=http://localhost:5000/oauth_callback")
        httpd.serve_forever()

if __name__ == '__main__':
    run_server()