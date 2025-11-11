# test_direct_connection.py
import urllib.request
import socket

def test_direct_connection():
    print("🔍 测试直接网络连接...")
    
    # 测试DNS解析
    try:
        ip = socket.gethostbyname('httpbin.org')
        print(f"✅ DNS解析成功: httpbin.org -> {ip}")
    except Exception as e:
        print(f"❌ DNS解析失败: {e}")
        return
    
    # 测试直接HTTP连接
    try:
        response = urllib.request.urlopen('http://httpbin.org/html', timeout=10)
        print(f"✅ 直接HTTP连接成功: 状态码 {response.status}")
        print(f"   内容长度: {len(response.read())} 字节")
    except Exception as e:
        print(f"❌ 直接HTTP连接失败: {e}")
    
    # 测试通过代理的连接
    try:
        proxy_handler = urllib.request.ProxyHandler({'http': 'http://127.0.0.1:8080'})
        opener = urllib.request.build_opener(proxy_handler)
        response = opener.open('http://httpbin.org/html', timeout=10)
        print(f"✅ 通过代理连接成功: 状态码 {response.status}")
        print(f"   内容长度: {len(response.read())} 字节")
    except Exception as e:
        print(f"❌ 通过代理连接失败: {e}")

if __name__ == '__main__':
    test_direct_connection()