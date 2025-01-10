import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Mail, User } from 'lucide-react';

const UserCard = ({ username, email, aboutme }) => {
  return (
    <Card className="w-full max-w-sm mx-auto hover:shadow-lg transition-shadow duration-200">
      <CardContent className="p-6">
        <div className="flex flex-col items-center text-center">
          {/* User Avatar */}
          <div className="w-20 h-20 bg-blue-100 rounded-full flex items-center justify-center mb-4">
            <User className="w-10 h-10 text-blue-500" />
          </div>

          {/* Username */}
          <h2 className="text-xl font-bold text-gray-800 mb-2">
            {username || '未知用戶'}
          </h2>

          {/* Email */}
          <div className="flex items-center text-gray-600 mb-4">
            <Mail className="w-4 h-4 mr-2" />
            <span>{email || '無電子郵件'}</span>
          </div>

          {/* About Me */}
          <div className="w-full">
            <p className="text-gray-600 text-sm leading-relaxed">
              {aboutme || '這個用戶很神秘，還沒有留下任何介紹...'}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

// 示例用法
const App = () => {
  const sampleUser = {
    username: "張小明",
    email: "xm.zhang@example.com",
    aboutme: "我是一個熱愛攝影和旅行的愛好者，喜歡分享生活中的美好時刻。"
  };

  return (
    <div className="p-4">
      <UserCard {...sampleUser} />
    </div>
  );
};

export default App;