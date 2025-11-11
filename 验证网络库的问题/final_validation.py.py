# final_validation.py
import urllib.request
import urllib3
import requests
import time
import json

def final_comprehensive_test():
    """最终综合验证"""
    print("🎯 urllib3最终验证测试")
    print("=" * 60)
    
    test_scenarios = [
        {
            "name": "基础HTTP请求",
            "url": "http://httpbin.org/ip",
            "expected_status": 200
        },
        {
            "name": "HTTPS安全请求", 
            "url": "https://httpbin.org/user-agent",
            "expected_status": 200
        },
        {
            "name": "重定向处理",
            "url": "http://httpbin.org/redirect/1",
            "expected_status": 200
        },
        {
            "name": "压缩内容",
            "url": "http://httpbin.org/gzip",
            "expected_status": 200
        }
    ]
    
    results = {
        'urllib': {'passed': 0, 'failed': 0, 'details': []},
        'urllib3': {'passed': 0, 'failed': 0, 'details': []},
        'requests': {'passed': 0, 'failed': 0, 'details': []}
    }
    
    for scenario in test_scenarios:
        print(f"\n📋 场景: {scenario['name']}")
        print(f"🔗 URL: {scenario['url']}")
        
        # urllib3测试
        print("  urllib3: ", end="")
        try:
            start_time = time.time()
            http = urllib3.PoolManager(timeout=10.0)
            response = http.request('GET', scenario['url'])
            elapsed = time.time() - start_time
            
            if response.status == scenario['expected_status']:
                results['urllib3']['passed'] += 1
                results['urllib3']['details'].append(f"✅ {scenario['name']} - {elapsed:.2f}s")
                print(f"✅ 通过 ({elapsed:.2f}s)")
            else:
                results['urllib3']['failed'] += 1
                results['urllib3']['details'].append(f"❌ {scenario['name']} - 状态码{response.status}")
                print(f"❌ 失败 - 状态码{response.status}")
                
        except Exception as e:
            results['urllib3']['failed'] += 1
            results['urllib3']['details'].append(f"❌ {scenario['name']} - {type(e).__name__}")
            print(f"❌ 异常 - {type(e).__name__}")
        
        # urllib测试
        print("  urllib:  ", end="")
        try:
            start_time = time.time()
            response = urllib.request.urlopen(scenario['url'], timeout=10)
            elapsed = time.time() - start_time
            
            if response.getcode() == scenario['expected_status']:
                results['urllib']['passed'] += 1
                results['urllib']['details'].append(f"✅ {scenario['name']} - {elapsed:.2f}s")
                print(f"✅ 通过 ({elapsed:.2f}s)")
            else:
                results['urllib']['failed'] += 1
                results['urllib']['details'].append(f"❌ {scenario['name']} - 状态码{response.getcode()}")
                print(f"❌ 失败 - 状态码{response.getcode()}")
                
        except Exception as e:
            results['urllib']['failed'] += 1
            results['urllib']['details'].append(f"❌ {scenario['name']} - {type(e).__name__}")
            print(f"❌ 异常 - {type(e).__name__}")
    
    # 输出最终结果
    print("\n" + "=" * 60)
    print("📊 最终测试结果")
    print("=" * 60)
    
    for lib, result in results.items():
        total = result['passed'] + result['failed']
        success_rate = (result['passed'] / total * 100) if total > 0 else 0
        print(f"\n{lib.upper():<10} 通过: {result['passed']}/{total} ({success_rate:.1f}%)")
        for detail in result['details']:
            print(f"  {detail}")

def generate_report():
    """生成测试报告"""
    print("\n📄 建议和结论")
    print("=" * 50)
    
    print("""
基于测试结果，建议如下：

1. ✅ 如果urllib3在所有测试中都成功：
   - urllib3是新项目的首选
   - 提供了更好的连接池、重试机制和错误处理
   - 在生产环境中更稳定可靠

2. ⚠️ 如果urllib3部分成功：
   - 检查网络环境和防火墙设置
   - 考虑使用requests（基于urllib3）
   - 根据具体失败场景调整配置

3. ❌ 如果urllib3完全失败：
   - 可能是系统级网络限制
   - 考虑使用requests作为替代
   - 检查代理和DNS设置

4. 🔧 通用建议：
   - 更新到最新版本的urllib3
   - 合理配置超时和重试策略
   - 在生产环境中启用适当的日志记录
   """)

if __name__ == "__main__":
    final_comprehensive_test()
    generate_report()