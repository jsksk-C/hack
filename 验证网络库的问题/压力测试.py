import concurrent.futures

def stress_test():
    """压力测试"""
    proxies = {'http': 'http://127.0.0.1:8080'}
    urls = [
        'http://httpbin.org/html',
        'http://httpbin.org/json',
        'http://example.com'
    ] * 10  # 30个请求
    
    def make_request(url):
        try:
            start = time.time()
            response = requests.get(url, proxies=proxies, timeout=10)
            duration = time.time() - start
            return f"✅ {url} - {response.status_code} - {duration:.2f}s"
        except Exception as e:
            return f"❌ {url} - 错误: {e}"
    
    print("开始压力测试...")
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(make_request, urls))
    
    total_time = time.time() - start_time
    print(f"\n压力测试完成 - 总时间: {total_time:.2f}s")
    
    for result in results:
        print(result)

# stress_test()  # 谨慎运行，可能会对目标网站造成压力