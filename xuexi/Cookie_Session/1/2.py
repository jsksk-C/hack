# 案例2：模拟登录流程
import requests
import time

def simulate_login():
    """模拟登录流程"""
    session = requests.Session()
    
    # 设置基础请求头
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    print("=== 模拟登录流程 ===")
    
    # 第一步：访问登录页面（获取初始Cookie）
    print("1. 访问登录页面...")
    login_page = session.get('https://httpbin.org/cookies/set/session_id=initial_123')
    print(f"   初始Cookie: {session.cookies.get_dict()}")
    
    # 第二步：提交登录表单
    print("2. 提交登录信息...")
    login_data = {
        'username': 'testuser',
        'password': 'testpass'
    }
    
    # 使用一个会返回我们提交数据的测试端点
    login_response = session.post(
        'https://httpbin.org/post', 
        data=login_data
    )
    
    result = login_response.json()
    print(f"   提交的表单数据: {result['form']}")
    print(f"   当前Cookie: {session.cookies.get_dict()}")
    
    # 第三步：访问需要登录的页面
    print("3. 访问用户页面...")
    user_page = session.get('https://httpbin.org/cookies')
    user_data = user_page.json()
    print(f"   服务器收到的Cookie: {user_data}")
    
    return session

# 运行登录模拟
session = simulate_login()