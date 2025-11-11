#案例1：基础Cookie操作

import requests

# 创建一个会话对象
session = requests.Session()

print("=== 基础Cookie操作 ===")

# 访问一个设置Cookie的测试网站
url = "https://httpbin.org/cookies/set?name=John&age=25"
response = session.get(url)

print("1. 服务器设置的Cookie:")
print(f"响应状态码: {response.status_code}")
print(f"会话中的Cookie: {session.cookies.get_dict()}")

# 访问查看Cookie的页面
url2 = "https://httpbin.org/cookies"
response2 = session.get(url2)

print("\n2. 发送给服务器的Cookie:")
print(f"响应内容: {response2.json()}")

# 手动添加Cookie
session.cookies.set('city', 'Beijing')
print(f"\n3. 手动添加Cookie后: {session.cookies.get_dict()}")

# 再次验证
response3 = session.get(url2)
print(f"4. 更新后的Cookie: {response3.json()}")