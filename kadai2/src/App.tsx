import UserCard from './components/UserCard'

function App() {
  const sampleUser = {
    username: "張小明",
    email: "xm.zhang@example.com",
    aboutme: "我是一個熱愛攝影和旅行的愛好者，喜歡分享生活中的美好時刻。"
  };

  return (
    <div className="p-4">
      <UserCard {...sampleUser} />
    </div>
  )
}

export default App