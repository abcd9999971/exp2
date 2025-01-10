import React from 'react';
import { User, Mail } from 'lucide-react';

interface UserCardProps {
    username: string;
    email: string;
    aboutme: string;
}

const UserCard: React.FC<UserCardProps> = ({ username, email, aboutme }) => {
    return (
        <div className="w-full max-w-sm mx-auto bg-white rounded-lg shadow-md p-6">
            <div className="flex flex-col items-center text-center">
                <div className="w-20 h-20 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                    <User className="w-10 h-10 text-blue-500" />
                </div>
                <h2 className="text-xl font-bold text-gray-800 mb-2">
                    {username || '未知用戶'}
                </h2>
                <div className="flex items-center text-gray-600 mb-4">
                    <Mail className="w-4 h-4 mr-2" />
                    <span>{email || '無電子郵件'}</span>
                </div>
                <div className="w-full">
                    <p className="text-gray-600 text-sm leading-relaxed">
                        {aboutme || '這個用戶很神秘，還沒有留下任何介紹...'}
                    </p>
                </div>
            </div>
        </div>
    );
};

export default UserCard;