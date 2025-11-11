# 案例4：模拟浏览器行为 - 完整的Cookie/Session管理
import requests

class BrowserSimulator:
    """模拟浏览器行为 - 完整的Cookie/Session管理"""
    
    def __init__(self):
        self.session = requests.Session()
        # 设置常见的浏览器头
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive'
        })
    
    def visit_page(self, url, description=""):
        """访问页面并显示Cookie信息"""
        print(f"\n📍 {description}")
        print(f"   访问: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            print(f"   状态码: {response.status_code}")
            
            # 显示Cookie变化
            cookies = self.session.cookies.get_dict()
            if cookies:
                print(f"   当前Cookie: {cookies}")
            else:
                print("   无Cookie")
                
            return response
        except Exception as e:
            print(f"   ❌ 错误: {e}")
            return None
    
    def login_simulation(self):
        """模拟登录过程"""
        print("=" * 60)
        print("🚀 开始模拟登录流程")
        print("=" * 60)
        
        # 1. 访问首页
        self.visit_page(
            'https://httpbin.org/cookies/set/welcome_visit=1', 
            "第一次访问网站"
        )
        
        # 2. 访问登录页
        self.visit_page(
            'https://httpbin.org/cookies/set/login_page=visited', 
            "访问登录页面"
        )
        
        # 3. 提交登录（模拟）
        print("\n🔐 提交登录表单")
        login_data = {
            'username': 'demo_user',
            'password': 'demo_pass',
            'remember_me': 'on'
        }
        
        # 使用会返回我们数据的测试端点
        response = self.session.post(
            'https://httpbin.org/post', 
            data=login_data
        )
        
        if response.status_code == 200:
            result = response.json()
            print("   ✅ 登录成功!")
            print(f"   提交的数据: {result['form']}")
        
        # 4. 登录后设置会话Cookie（模拟服务器设置登录状态）
        self.visit_page(
            'https://httpbin.org/cookies/set/session_token=logged_in_abc123', 
            "服务器设置登录状态"
        )
        
        # 5. 访问用户中心（需要登录）
        user_response = self.visit_page(
            'https://httpbin.org/cookies', 
            "访问用户中心"
        )
        
        if user_response:
            cookies_received = user_response.json().get('cookies', {})
            print(f"   📋 服务器收到的Cookie: {cookies_received}")
            
            # 检查登录状态
            if 'session_token' in cookies_received:
                print("   ✅ 登录状态有效!")
            else:
                print("   ❌ 未检测到登录状态")

# 运行模拟
browser = BrowserSimulator()
browser.login_simulation()