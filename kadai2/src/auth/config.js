export const authConfig = {
    // 替換成你的 OAuth provider 設定
    clientId: 'your_client_id',
    authorizationEndpoint: 'https://provider.com/oauth/authorize', //換成microblog的授權網址
    tokenEndpoint: 'https://provider.com/oauth/token', 
    redirectUri: 'http://localhost:5173/callback',
    scope: 'profile' // 根據需求調整權限範圍
  };
