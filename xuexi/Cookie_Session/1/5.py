# 案例5：学习Cookie的各种属性
import requests
from http.cookies import SimpleCookie

def learn_cookie_attributes():
    """学习Cookie的各种属性"""
    
    print("=== Cookie属性学习 ===")
    
    # 创建自定义Cookie
    rawdata = "user=john; Path=/; Domain=.example.com; Max-Age=3600; Secure; HttpOnly"
    cookie = SimpleCookie()
    cookie.load(rawdata)
    
    print("1. Cookie解析:")
    for key, morsel in cookie.items():
        print(f"   Key: {key}")
        print(f"   Value: {morsel.value}")
        print(f"   属性: {dict(morsel)}")
    
    # 使用requests设置带属性的Cookie
    session = requests.Session()
    
    # 注意：requests不能直接设置HttpOnly等属性，这些由服务器设置
    # 但我们可以了解这些属性的作用
    
    print("\n2. Cookie属性说明:")
    attributes = {
        'Path': '指定Cookie的有效路径',
        'Domain': '指定Cookie的有效域名', 
        'Max-Age': 'Cookie的有效期（秒）',
        'Expires': 'Cookie的过期时间',
        'Secure': '仅通过HTTPS传输',
        'HttpOnly': '阻止JavaScript访问',
        'SameSite': '控制跨站请求时Cookie的发送'
    }
    
    for attr, desc in attributes.items():
        print(f"   {attr}: {desc}")
    
    # 实际演示
    print("\n3. 实际Cookie示例:")
    response = session.get('https://httpbin.org/cookies')
    print(f"   服务器设置的Cookie: {response.headers.get('Set-Cookie', '无')}")

learn_cookie_attributes()

"""
Cookie
存储在客户端（浏览器）的小段数据
作用：记录用户状态、登录信息、偏好设置等
特点：每次请求都会自动发送给服务器

Session
存储在服务器端的用户会话数据
作用：在服务器端维护用户状态
实现方式：通常通过Session ID（存储在Cookie中）来识别用户
"""