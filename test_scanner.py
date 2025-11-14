#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
测试脚本 - 验证dirscanner包的功能
"""

import asyncio
import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_basic_functionality():
    """测试基本功能"""
    print("=== 开始测试dirscanner包 ===")
    
    try:
        # 测试导入
        print("测试模块导入...")
        from dirscanner import (
            AdvancedDirectoryScanner,
            ScanResult,
            SmartResponseAnalyzer,
            ResultAnalyzer,
            DynamicWordlistGenerator,
            ReportGenerator,
            AuthHandler,
            ProxyManager,
            AdaptiveRateLimiter
        )
        print("✓ 模块导入成功")
        
        # 测试类初始化
        print("\n测试类初始化...")
        
        # 测试DynamicWordlistGenerator
        print("测试DynamicWordlistGenerator...")
        generator = DynamicWordlistGenerator("https://example.com")
        words = generator.generate_target_specific_words()
        print(f"✓ 动态字典生成成功，生成了 {len(words)} 个单词")
        
        # 测试SmartResponseAnalyzer
        print("测试SmartResponseAnalyzer...")
        analyzer = SmartResponseAnalyzer("https://example.com")
        print("✓ SmartResponseAnalyzer初始化成功")
        
        # 测试ProxyManager
        print("测试ProxyManager...")
        proxy_manager = ProxyManager(["http://127.0.0.1:8080"])
        print("✓ ProxyManager初始化成功")
        
        # 测试AdaptiveRateLimiter
        print("测试AdaptiveRateLimiter...")
        rate_limiter = AdaptiveRateLimiter(10, 1, 50)
        print(f"✓ AdaptiveRateLimiter初始化成功，当前速率: {rate_limiter.get_current_rate()}")
        
        # 测试ScanResult
        print("测试ScanResult...")
        result = ScanResult(
            url="https://example.com/test",
            status=200,
            content_length=1000,
            content_type="text/html",
            title="Test Page",
            redirect_url="",
            response_time=100.5
        )
        result_dict = result.to_dict()
        print(f"✓ ScanResult初始化成功，状态码: {result.status}")
        
        # 测试AuthHandler
        print("测试AuthHandler...")
        auth_handler = AuthHandler()
        auth_handler.set_basic_auth("testuser", "testpass")
        headers = auth_handler.get_auth_headers()
        print(f"✓ AuthHandler设置认证成功，认证头数量: {len(headers)}")
        
        # 测试ReportGenerator
        print("测试ReportGenerator...")
        report_generator = ReportGenerator()
        print("✓ ReportGenerator初始化成功")
        
        print("\n=== 所有基本功能测试通过 ===")
        print("\n注意: 完整的扫描功能需要实际运行，请使用以下命令测试:")
        print("python scan.py https://example.com -t 5 -o test_result.json")
        
    except Exception as e:
        print(f"✗ 测试失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

def main():
    """主测试函数"""
    # 处理Windows兼容性
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    success = asyncio.run(test_basic_functionality())
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())