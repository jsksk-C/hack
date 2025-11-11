# 案例3：Session持久化
import requests
import pickle
import os

class SessionManager:
    """Session管理器 - 学习Cookie持久化"""
    
    def __init__(self, session_file='session.pkl'):
        self.session_file = session_file
        self.session = requests.Session()
        self.load_session()
    
    def load_session(self):
        """从文件加载Session"""
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, 'rb') as f:
                    self.session = pickle.load(f)
                print(f"✅ 从 {self.session_file} 加载Session成功")
                print(f"   当前Cookie: {self.session.cookies.get_dict()}")
            except Exception as e:
                print(f"❌ 加载Session失败: {e}")
                self.session = requests.Session()
        else:
            print("📝 创建新Session")
    
    def save_session(self):
        """保存Session到文件"""
        try:
            with open(self.session_file, 'wb') as f:
                pickle.dump(self.session, f)
            print(f"💾 Session已保存到 {self.session_file}")
        except Exception as e:
            print(f"❌ 保存Session失败: {e}")
    
    def make_request(self, url):
        """使用Session发送请求"""
        print(f"\n🌐 访问: {url}")
        response = self.session.get(url)
        print(f"   状态码: {response.status_code}")
        print(f"   当前Cookie: {self.session.cookies.get_dict()}")
        return response

# 使用Session管理器
print("=== Session持久化演示 ===")
manager = SessionManager()

# 第一次访问 - 设置Cookie
manager.make_request('https://httpbin.org/cookies/set/user_id=1001')
manager.make_request('https://httpbin.org/cookies/set/token=abc123')

# 保存Session
manager.save_session()

print("\n" + "="*50)
print("模拟程序重启...")
print("="*50)

# 模拟程序重启后重新加载Session
manager2 = SessionManager()

# 验证Cookie是否保持
manager2.make_request('https://httpbin.org/cookies')

# 清理
if os.path.exists('session.pkl'):
    os.remove('session.pkl')
    print("\n🧹 已清理临时文件")