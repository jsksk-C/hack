import urllib.request
import requests
import time

def compare_requests_vs_urllib():
    """对比requests和urllib的表现"""
    print("📊 对比requests vs urllib...")
    
    test_urls = [
        "http://httpbin.org/ip",
        "http://httpbin.org/html",
        "http://example.com"
    ]
    
    for url in test_urls:
        print(f"\n🔗 测试: {url}")
        
        # 测试urllib
        print("  urllib:", end=" ")
        try:
            start_time = time.time()
            response = urllib.request.urlopen(url, timeout=10)
            elapsed = time.time() - start_time
            print(f"✅ 成功 ({response.getcode()}), 耗时: {elapsed:.2f}s")
        except Exception as e:
            print(f"❌ 失败: {type(e).__name__}")
        
        # 测试requests
        print("  requests:", end=" ")
        try:
            start_time = time.time()
            response = requests.get(url, timeout=10)
            elapsed = time.time() - start_time
            print(f"✅ 成功 ({response.status_code}), 耗时: {elapsed:.2f}s")
        except Exception as e:
            print(f"❌ 失败: {type(e).__name__}")

def test_requests_with_proxy():
    """测试requests库在代理环境下的表现"""
    print("\n🌐 测试requests在代理环境下...")
    
    # 设置系统代理（模拟你的代理服务器环境）
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    
    try:
        # 通过代理发送请求
        response = requests.get(
            "http://httpbin.org/ip",
            proxies=proxies,
            timeout=10
        )
        print(f"✅ 通过代理成功: {response.status_code}")
        print(f"   响应: {response.text[:100]}...")
    except Exception as e:
        print(f"❌ 代理请求失败: {e}")

if __name__ == "__main__":
    compare_requests_vs_urllib()
    test_requests_with_proxy()