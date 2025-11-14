# -*- coding: utf-8 -*-
"""
主入口模块
"""

import argparse
import asyncio
import sys
import os
from typing import List

from .scanner import AdvancedDirectoryScanner, load_wordlist, load_proxy_list
from .generators import ReportGenerator

async def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='高级目录扫描工具')
    parser.add_argument('url', help='目标URL')
    parser.add_argument('-w', '--wordlist', help='字典文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径 (JSON格式)')
    parser.add_argument('-c', '--csv', help='CSV格式输出文件路径')
    parser.add_argument('-H', '--html', help='HTML格式输出文件路径')
    parser.add_argument('-t', '--threads', type=int, default=10, help='并发线程数 (默认: 10)')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='请求超时时间 (秒，默认: 10)')
    parser.add_argument('-r', '--retries', type=int, default=3, help='最大重试次数 (默认: 3)')
    parser.add_argument('-p', '--proxy', help='代理服务器地址 (格式: http://host:port)')
    parser.add_argument('-P', '--proxy-file', help='包含代理列表的文件路径')
    parser.add_argument('-f', '--follow-redirects', action='store_true', help='跟随重定向')
    parser.add_argument('-A', '--user-agent', help='自定义User-Agent')
    parser.add_argument('-hH', '--header', action='append', help='自定义HTTP头信息 (格式: Key:Value)')
    parser.add_argument('-a', '--auth', help='基础认证信息 (格式: username:password)')
    parser.add_argument('-b', '--bearer', help='Bearer令牌')
    parser.add_argument('--max-time', type=int, help='扫描最大运行时间 (秒)')
    
    args = parser.parse_args()
    
    # 处理代理设置
    proxy_list = []
    if args.proxy:
        proxy_list.append(args.proxy)
    if args.proxy_file:
        proxy_list.extend(load_proxy_list(args.proxy_file))
    
    # 处理自定义头信息
    headers = {}
    if args.user_agent:
        headers['User-Agent'] = args.user_agent
    if args.header:
        for header in args.header:
            try:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
            except ValueError:
                print(f"警告: 无效的头信息格式: {header}")
    
    # 初始化扫描器
    scanner = AdvancedDirectoryScanner(
        target_url=args.url,
        wordlist_path=args.wordlist,
        concurrency=args.threads,
        timeout=args.timeout,
        max_retries=args.retries,
        proxy_list=proxy_list,
        follow_redirects=args.follow_redirects,
        headers=headers
    )
    
    # 设置认证
    if args.auth:
        try:
            username, password = args.auth.split(':', 1)
            scanner.auth_handler.set_basic_auth(username, password)
        except ValueError:
            print(f"警告: 无效的认证格式，应为 username:password")
    if args.bearer:
        scanner.auth_handler.set_bearer_token(args.bearer)
    
    try:
        # 初始化并运行扫描
        if await scanner.initialize():
            results = await scanner.run_scan_with_timeout(args.max_time)
            
            # 生成报告
            if results:
                stats = scanner.get_stats()
                report_generator = ReportGenerator()
                    
                # 根据文件扩展名自动选择报告格式
                if args.output:
                    if args.output.endswith('.html'):
                        report_generator.generate_html_report(results, stats, args.output)
                        print(f"\nHTML报告已保存到: {args.output}")
                    elif args.output.endswith('.csv'):
                        report_generator.generate_csv_report(results, stats, args.output)
                        print(f"\nCSV报告已保存到: {args.output}")
                    else:
                        # 默认生成JSON报告
                        report_generator.generate_json_report(results, stats, args.output)
                        print(f"\nJSON报告已保存到: {args.output}")
                
                # 特定格式报告参数（向后兼容）
                if args.csv:
                    report_generator.generate_csv_report(results, stats, args.csv)
                    print(f"CSV报告已保存到: {args.csv}")
                
                if args.html:
                    report_generator.generate_html_report(results, stats, args.html)
                    print(f"HTML报告已保存到: {args.html}")
            
            # 打印摘要
            scanner.print_summary()
    
    except KeyboardInterrupt:
        print("\n扫描被用户中断")
    except Exception as e:
        print(f"\n扫描过程中发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # 关闭扫描器
        await scanner.close()

def run():
    """运行函数，处理Windows平台的兼容性"""
    # 在Windows平台上，使用不同的事件循环策略
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    # 运行主函数
    asyncio.run(main())

if __name__ == '__main__':
    run()