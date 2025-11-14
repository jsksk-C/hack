# -*- coding: utf-8 -*-
"""
扫描器模块
"""

import asyncio
import aiohttp
import time
import signal
import sys
import traceback
import random
from typing import List, Optional, Dict, Set
from urllib.parse import urljoin, urlparse
from datetime import datetime

from .models import ScanResult
from .analyzers import SmartResponseAnalyzer
from .generators import DynamicWordlistGenerator
from .managers import AuthHandler, ProxyManager, AdaptiveRateLimiter

class AdvancedDirectoryScanner:
    """高级目录扫描器"""
    
    def __init__(self, target_url: str, wordlist_path: Optional[str] = None,
                 concurrency: int = 10, timeout: int = 10, max_retries: int = 3,
                 proxy_list: Optional[List[str]] = None, follow_redirects: bool = False,
                 headers: Optional[Dict[str, str]] = None):
        
        # 初始化基本参数
        self.target_url = self._normalize_url(target_url)
        self.wordlist_path = wordlist_path
        self.concurrency = concurrency
        self.timeout = timeout
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        
        # 初始化组件
        self.auth_handler = AuthHandler()
        self.proxy_manager = ProxyManager(proxy_list)
        self.rate_limiter = AdaptiveRateLimiter()
        self.response_analyzer = SmartResponseAnalyzer(self.target_url)
        
        # 初始化状态变量
        self.session = None
        self.results = []
        self.tasks = set()
        self.semaphore = None
        self.should_stop = False
        self.start_time = 0
        self.end_time = 0
        self.requests_sent = 0
        self.requests_failed = 0
        self.meaningful_responses = 0
        
        # 初始化默认头信息
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0'
        }
        
        # 合并自定义头信息
        if headers:
            self.headers.update(headers)
        
        # 添加认证头信息
        self.headers.update(self.auth_handler.get_auth_headers())
        
        # 注册信号处理
        self._register_signal_handlers()
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL格式"""
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
        if not url.endswith('/'):
            url = f'{url}/'
        return url
    
    def _register_signal_handlers(self):
        """注册信号处理程序"""
        try:
            if sys.platform != 'win32':  # Windows不支持SIGTERM等信号
                signal.signal(signal.SIGINT, self._handle_signal)
                signal.signal(signal.SIGTERM, self._handle_signal)
        except:
            # 在某些环境中可能无法注册信号处理程序
            pass
    
    def _handle_signal(self, signum, frame):
        """处理终止信号"""
        print("\n收到终止信号，正在停止扫描...")
        self.should_stop = True
    
    async def initialize(self) -> bool:
        """初始化扫描器"""
        print(f"\n正在初始化扫描器...")
        print(f"目标: {self.target_url}")
        
        # 创建会话
        connector = aiohttp.TCPConnector(limit=self.concurrency * 2, ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        
        # 创建信号量
        self.semaphore = asyncio.Semaphore(self.concurrency)
        
        # 测试连接
        if not await self._test_connection():
            print("连接测试失败，无法连接到目标服务器")
            await self.session.close()
            return False
        
        # 建立404基线
        if not await self.response_analyzer.establish_baseline(self.session, self.headers):
            print("警告: 无法建立404基线，将使用默认判断规则")
            
        print("扫描器初始化完成")
        return True
    
    async def _test_connection(self) -> bool:
        """测试与目标的连接"""
        try:
            async with self.session.get(self.target_url, headers=self.headers) as response:
                await response.text()
                print(f"连接测试成功: {response.status}")
                return True
        except Exception as e:
            print(f"连接测试失败: {str(e)}")
            return False
    
    def _load_wordlist(self) -> List[str]:
        """加载字典列表"""
        words = []
        
        # 如果提供了字典文件路径，则加载文件
        if self.wordlist_path:
            try:
                with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                    words = [line.strip() for line in f if line.strip()]
                print(f"从文件加载了 {len(words)} 个路径")
            except Exception as e:
                print(f"无法加载字典文件: {str(e)}")
        
        # 如果文件加载失败或没有提供文件，则使用动态生成的字典
        if not words:
            print("使用动态生成的字典")
            generator = DynamicWordlistGenerator(self.target_url)
            words = generator.generate_target_specific_words()
        
        return words
    
    async def scan_url(self, url: str) -> Optional[ScanResult]:
        """扫描单个URL"""
        if self.should_stop:
            return None
        
        # 检查速率限制
        if self.rate_limiter.should_delay():
            delay = self.rate_limiter.get_delay_time()
            await asyncio.sleep(delay)
        
        result = None
        retry_count = 0
        
        while retry_count <= self.max_retries and not self.should_stop:
            proxy = self.proxy_manager.get_next_proxy()
            proxy_dict = self.proxy_manager.format_proxy_for_aiohttp(proxy) if proxy else None
            
            try:
                start_time = time.time()
                
                async with self.semaphore:
                    async with self.session.get(url, headers=self.headers, 
                                              allow_redirects=self.follow_redirects,
                                              proxy=proxy_dict) as response:
                        
                        # 记录响应时间
                        response_time = (time.time() - start_time) * 1000  # 转换为毫秒
                        
                        # 读取响应内容
                        content = await response.read()
                        content_length = len(content)
                        
                        # 获取内容类型
                        content_type = response.headers.get('Content-Type', 'unknown')
                        
                        # 获取重定向URL
                        redirect_url = response.headers.get('Location', '') if response.status in [301, 302, 303, 307, 308] else ''
                        
                        # 尝试提取标题
                        title = self._extract_title(content)
                        
                        # 创建结果对象
                        result = ScanResult(
                            url=url,
                            status=response.status,
                            content_length=content_length,
                            content_type=content_type,
                            title=title,
                            redirect_url=redirect_url,
                            response_time=response_time,
                            content=content
                        )
                        
                        # 分析响应是否有意义
                        if self.response_analyzer.is_meaningful_response(result, content):
                            result.is_meaningful = True
                            self.meaningful_responses += 1
                            
                            # 评估风险等级
                            from .analyzers import ResultAnalyzer
                            result_analyzer = ResultAnalyzer()
                            result.risk_level = result_analyzer.assess_risk(result.url, result.status, result.content_length)
                        
                        # 更新代理状态
                        if proxy:
                            self.proxy_manager.mark_proxy_successful(proxy)
                        
                        # 记录成功请求
                        self.rate_limiter.record_request(True)
                        return result
                        
            except asyncio.TimeoutError:
                retry_count += 1
                print(f"超时重试 {retry_count}/{self.max_retries}: {url}")
                
            except aiohttp.ClientError as e:
                retry_count += 1
                print(f"请求错误重试 {retry_count}/{self.max_retries}: {url} - {str(e)}")
                
                # 标记代理失败
                if proxy:
                    self.proxy_manager.mark_proxy_failed(proxy)
                    
            except Exception as e:
                retry_count += 1
                print(f"未知错误重试 {retry_count}/{self.max_retries}: {url} - {str(e)}")
            
            # 记录失败请求
            self.rate_limiter.record_request(False)
            
            # 重试前等待
            if retry_count <= self.max_retries:
                await asyncio.sleep(random.uniform(0.5, 2.0))
        
        # 达到最大重试次数
        if result is None:
            self.requests_failed += 1
        
        return result
    
    def _extract_title(self, content: bytes) -> str:
        """从HTML内容中提取标题"""
        try:
            content_str = content.decode('utf-8', errors='ignore')
            start_tag = '<title>'
            end_tag = '</title>'
            
            start_idx = content_str.lower().find(start_tag)
            if start_idx != -1:
                start_idx += len(start_tag)
                end_idx = content_str.lower().find(end_tag, start_idx)
                if end_idx != -1:
                    return content_str[start_idx:end_idx].strip()[:100]  # 限制标题长度
        except:
            pass
        
        return ''
    
    async def run_scan(self) -> List[ScanResult]:
        """运行扫描"""
        # 加载字典
        words = self._load_wordlist()
        print(f"开始扫描，共 {len(words)} 个路径")
        
        # 记录开始时间
        self.start_time = time.time()
        
        # 创建任务
        tasks = []
        for word in words:
            if self.should_stop:
                break
                
            # 构建URL
            if word.startswith('/'):
                url = self.target_url[:-1] + word  # 如果路径已以/开头，就不再添加/
            else:
                url = urljoin(self.target_url, word)
            
            task = asyncio.create_task(self.scan_url(url))
            tasks.append(task)
            self.requests_sent += 1
            
            # 打印进度
            if self.requests_sent % 100 == 0:
                print(f"已发送 {self.requests_sent}/{len(words)} 个请求")
        
        # 等待任务完成
        for task in asyncio.as_completed(tasks):
            if self.should_stop:
                break
                
            try:
                result = await task
                if result:
                    self.results.append(result)
                    if result.is_meaningful:
                        self._print_result(result)
            except Exception as e:
                print(f"处理任务时出错: {str(e)}")
        
        # 记录结束时间
        self.end_time = time.time()
        
        # 取消未完成的任务
        if self.should_stop:
            for task in tasks:
                if not task.done():
                    task.cancel()
        
        return self.results
    
    async def run_scan_with_timeout(self, timeout: Optional[int] = None) -> List[ScanResult]:
        """带超时的扫描运行"""
        try:
            if timeout:
                scan_task = asyncio.create_task(self.run_scan())
                result = await asyncio.wait_for(scan_task, timeout=timeout)
                return result
            else:
                return await self.run_scan()
        except asyncio.TimeoutError:
            print("扫描超时")
            self._stop_scan()
            return self.results
    
    def _print_result(self, result: ScanResult):
        """打印结果"""
        status_color = {
            200: '\033[92m',  # 绿色
            301: '\033[93m',  # 黄色
            302: '\033[93m',  # 黄色
            401: '\033[91m',  # 红色
            403: '\033[91m',  # 红色
            500: '\033[91m',  # 红色
        }
        
        color = status_color.get(result.status, '\033[0m')  # 默认颜色
        reset = '\033[0m'
        
        # 针对Windows命令提示符，简化输出
        if sys.platform == 'win32':
            print(f"发现: {result.url} - 状态: {result.status} - 长度: {result.content_length}")
        else:
            print(f"{color}发现: {result.url} - 状态: {result.status} - 长度: {result.content_length}{reset}")
    
    def _stop_scan(self):
        """停止扫描"""
        self.should_stop = True
        
        # 取消所有任务
        for task in self.tasks:
            if not task.done():
                task.cancel()
    
    async def close(self):
        """关闭扫描器资源"""
        if self.session:
            await self.session.close()
    
    def get_stats(self) -> Dict:
        """获取扫描统计信息"""
        duration = self.end_time - self.start_time if self.end_time else time.time() - self.start_time
        meaningful_results = [r for r in self.results if r.is_meaningful]
        
        return {
            'target': self.target_url,
            'start_time': self.start_time,
            'duration': duration,
            'requests_sent': self.requests_sent,
            'requests_failed': self.requests_failed,
            'meaningful_responses': len(meaningful_results),
            'requests_per_second': self.requests_sent / duration if duration > 0 else 0
        }
    
    def print_summary(self):
        """打印扫描摘要"""
        stats = self.get_stats()
        
        print("\n=== 扫描完成 ===")
        print(f"目标: {stats['target']}")
        print(f"扫描时长: {stats['duration']:.2f} 秒")
        print(f"发送请求数: {stats['requests_sent']}")
        print(f"失败请求数: {stats['requests_failed']}")
        print(f"有意义的响应: {stats['meaningful_responses']}")
        print(f"请求速率: {stats['requests_per_second']:.2f} 请求/秒")
        
        # 统计不同状态码的数量
        status_count = {}
        for result in self.results:
            if result.is_meaningful:
                status_count[result.status] = status_count.get(result.status, 0) + 1
        
        if status_count:
            print("\n状态码统计:")
            for status, count in sorted(status_count.items()):
                print(f"  {status}: {count} 个")

# 辅助函数
def load_wordlist(file_path: str) -> List[str]:
    """加载字典文件"""
    words = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"加载字典文件时出错: {str(e)}")
    return words

def load_proxy_list(file_path: str) -> List[str]:
    """加载代理列表"""
    proxies = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            proxies = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"加载代理文件时出错: {str(e)}")
    return proxies