#!/usr/bin/env python3
"""
高级目录扫描工具 - Windows优化完整版本
作者：基于您的需求优化实现
"""

import asyncio
import aiohttp
import argparse
import json
import time
import random
import hashlib
import re
import os
import sys
import threading
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
from collections import deque, defaultdict
import logging
import csv
from pathlib import Path
import warnings

# 忽略特定警告
warnings.filterwarnings('ignore', category=DeprecationWarning, module='aiohttp')

# Windows特定导入
if sys.platform == 'win32':
    try:
        import win32api
        HAS_WIN32 = True
    except ImportError:
        HAS_WIN32 = False
else:
    import signal
    HAS_WIN32 = False

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,  # 设置为DEBUG级别，显示详细调试信息
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dirscan.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """扫描结果数据类"""
    url: str
    status: int
    content_length: int
    content_type: str = ""
    title: str = ""
    redirect_url: str = ""
    headers: Dict = None
    response_time: float = 0.0
    risk_level: str = "info"
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return asdict(self)

class SmartResponseAnalyzer:
    """智能响应分析器"""
    
    def __init__(self):
        self.baseline_404 = None
        self.fingerprints = set()
        self.similarity_threshold = 0.85
        self.common_404_patterns = [
            r'not found', r'404', r'error', r'找不到', r'页面不存在',
            r'object not found', r'file not found', r'page not found',
            r'resource not found', r'无法找到', r'未找到', r'不存在'
        ]
        
    async def establish_baseline(self, base_url: str, session: aiohttp.ClientSession) -> bool:
        """建立404页面基线"""
        test_paths = [
            f"/{hashlib.md5(str(random.random()).encode()).hexdigest()[:16]}",
            f"/{int(time.time()*1000)}",
            "/this-path-should-not-exist-12345",
            "/nonexistent-path-abcdef",
            "/random-path-987654321"
        ]
        
        logger.info("正在测试404基线...")
        for i, path in enumerate(test_paths):
            try:
                test_url = urljoin(base_url, path)
                logger.debug(f"基线测试 {i+1}/{len(test_paths)}: {test_url}")
                
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    content = await response.text()
                    fingerprint = self._create_fingerprint(content, response.headers)
                    self.fingerprints.add(fingerprint)
                    
                    if self.baseline_404 is None:
                        self.baseline_404 = {
                            'status': response.status,
                            'length': len(content),
                            'fingerprint': fingerprint,
                            'headers': dict(response.headers)
                        }
                        logger.debug(f"建立基线: 状态码={response.status}, 长度={len(content)}")
                    
            except asyncio.TimeoutError:
                logger.debug(f"基线测试超时: {test_url}")
            except Exception as e:
                logger.debug(f"基线测试失败: {test_url} - {e}")
        
        success = self.baseline_404 is not None
        logger.info(f"基线建立{'成功' if success else '失败'}")
        return success
    
    def _create_fingerprint(self, content: str, headers: Dict) -> str:
        """创建响应指纹"""
        # 提取关键特征
        features = []
        
        # 内容长度
        features.append(f"len:{len(content)}")
        
        # 标题标签
        title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
        if title_match:
            features.append(f"title:{title_match.group(1).lower()[:50]}")
        
        # 特定关键词
        for keyword in self.common_404_patterns:
            if keyword.lower() in content.lower():
                features.append(f"kw:{keyword}")
        
        # 头部特征
        if 'Server' in headers:
            features.append(f"server:{headers['Server']}")
        
        return hashlib.md5('|'.join(features).encode()).hexdigest()
    
    def is_meaningful_response(self, result: ScanResult, content: str) -> bool:
        """判断响应是否有意义（不是404或错误页面）"""
        # 状态码为200的响应总是有意义的
        if result.status == 200:
            return True
        
        # 如果状态码明确是404
        if result.status == 404:
            return False
        
        # 创建当前响应指纹
        current_fp = self._create_fingerprint(content, result.headers or {})
        
        # 与已知404指纹比较
        for fp in self.fingerprints:
            if current_fp == fp:
                return False
        
        # 长度相似性检查 - 进一步降低阈值以适应更多网站
        if self.baseline_404 and result.content_length > 0:
            baseline_len = self.baseline_404.get('length', 0)
            if baseline_len > 0:
                similarity = min(baseline_len, result.content_length) / max(baseline_len, result.content_length)
                # 进一步降低阈值从0.75到0.65，允许更多潜在的有效响应
                if similarity > 0.65:
                    return False
        
        # 状态码过滤 - 放宽限制，允许3xx重定向和更多类型的响应
        if result.status >= 400 and result.status not in [401, 403, 405, 500, 503]:
            return False
        
        # 额外检查：如果状态码是3xx重定向，也视为有意义的响应
        if 300 <= result.status < 400 and result.redirect_url:
            return True
            
        return True

class DynamicWordlistGenerator:
    """动态字典生成器"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.target_name = self._extract_target_name()
        self.common_dirs = self._load_common_directories()
        self.common_files = self._load_common_files()
    
    def _extract_target_name(self) -> str:
        """从URL提取目标名称"""
        parsed = urlparse(self.target_url)
        domain = parsed.netloc
        
        # 移除端口号
        domain = domain.split(':')[0]
        
        # 提取主域名部分
        parts = domain.split('.')
        if len(parts) >= 2:
            # 对于类似 www.example.com 的情况，取 example
            if parts[0] in ['www', 'api', 'app', 'test', 'dev', 'staging']:
                return parts[1] if len(parts) > 1 else parts[0]
            return parts[0]
        return domain
    
    def _load_common_directories(self) -> List[str]:
        """加载常见目录列表"""
        return [
            # 管理后台
            'admin', 'administrator', 'admincp', 'adminpanel', 'manager', 
            'management', 'dashboard', 'control', 'console', 'backend',
            'webadmin', 'cpanel', 'panel', 'login', 'logon', 'signin',
            
            # 配置目录
            'config', 'configuration', 'settings', 'setup', 'install',
            'installer', 'update', 'upgrade', 'etc', 'conf',
            
            # 备份目录
            'backup', 'backups', 'bak', 'old', 'archive', 'archives',
            'back', 'backup_old', 'database_backup', 'db_backup',
            
            # 源码目录
            'src', 'source', 'code', 'develop', 'development', 'dev',
            'build', 'dist', 'app', 'application', 'apps', 'web',
            'www', 'public', 'public_html', 'html', 'htdocs',
            
            # API目录
            'api', 'apis', 'rest', 'json', 'xml', 'soap', 'webservice',
            
            # 静态资源
            'assets', 'static', 'media', 'upload', 'uploads', 'files',
            'images', 'img', 'css', 'js', 'javascript', 'fonts',
            
            # 系统目录
            'bin', 'boot', 'lib', 'opt', 'proc', 'root', 'sbin', 'usr', 'var',
            
            # 测试文档
            'test', 'tests', 'testing', 'docs', 'document', 'doc', 'wiki',
            
            # 版本控制
            '.git', '.svn', '.hg', '.cvs',
            
            # CMS相关
            'wp-admin', 'wp-content', 'wp-includes', 'administrator',
            'sites', 'modules', 'themes', 'plugins', 'components'
        ]
    
    def _load_common_files(self) -> List[str]:
        """加载常见文件列表"""
        return [
            # 配置文件
            'config.php', 'config.json', 'config.xml', 'config.yml',
            'config.ini', 'settings.php', 'database.php', 'db.php',
            '.env', '.env.local', '.env.production',
            
            # 备份文件
            'backup.sql', 'backup.zip', 'backup.tar', 'backup.tar.gz',
            'dump.sql', 'database_dump.sql',
            
            # 管理文件
            'admin.php', 'administrator.php', 'login.php', 'panel.php',
            'index.php', 'index.html', 'default.html', 'home.html',
            
            # 信息文件
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'security.txt', 'humans.txt', 'favicon.ico',
            
            # 日志文件
            'error.log', 'access.log', 'debug.log',
            
            # 版本控制
            '.gitignore', '.git/config', '.svn/entries',
            
            # 服务器配置
            '.htaccess', 'web.config', 'httpd.conf'
        ]
    
    def generate_target_specific_words(self) -> List[str]:
        """生成目标特定的字典"""
        words = set()
        target_name = self.target_name.lower()
        
        if not target_name or target_name in ['localhost', '127.0.0.1']:
            return list(set(self.common_dirs + self.common_files))
        
        # 基于目标名称的变体
        target_variants = [
            target_name,
            f"{target_name}-admin", f"{target_name}-panel", f"{target_name}-login",
            f"{target_name}-backup", f"{target_name}-test", f"{target_name}-dev",
            f"admin-{target_name}", f"backup-{target_name}", f"test-{target_name}",
            f"dev-{target_name}", f"staging-{target_name}", f"prod-{target_name}",
            f"{target_name}2023", f"{target_name}2024", f"{target_name}_backup",
            f"{target_name}_old", f"{target_name}_new", f"{target_name}_test"
        ]
        
        # 添加常见目录和文件
        words.update(self.common_dirs)
        words.update(self.common_files)
        words.update(target_variants)
        
        # 生成带扩展名的文件变体
        file_variants = []
        extensions = ['.php', '.asp', '.aspx', '.jsp', '.html', '.txt', '.bak', '.old']
        
        for word in list(words):
            if not any(word.endswith(ext) for ext in extensions) and '.' not in word:
                for ext in extensions:
                    file_variants.append(f"{word}{ext}")
        
        words.update(file_variants)
        
        return list(words)

class AuthHandler:
    """认证处理器"""
    
    def __init__(self):
        self.auth_headers = {}
        self.cookies = {}
    
    def set_basic_auth(self, username: str, password: str):
        """设置基本认证"""
        import base64
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.auth_headers['Authorization'] = f"Basic {credentials}"
    
    def set_bearer_token(self, token: str):
        """设置Bearer Token"""
        self.auth_headers['Authorization'] = f"Bearer {token}"
    
    def set_api_key(self, key: str, header_name: str = 'X-API-Key'):
        """设置API密钥"""
        self.auth_headers[header_name] = key
    
    def set_cookies(self, cookies: Dict[str, str]):
        """设置Cookies"""
        self.cookies.update(cookies)
    
    def get_headers(self) -> Dict[str, str]:
        """获取认证头"""
        return self.auth_headers.copy()
    
    def get_cookies(self) -> Dict[str, str]:
        """获取Cookies"""
        return self.cookies.copy()

class ProxyManager:
    """代理管理器"""
    
    def __init__(self, proxy_list: List[str] = None):
        self.proxies = proxy_list or []
        self.current_index = 0
        self.failed_proxies = set()
        self.lock = threading.Lock()
    
    def get_next_proxy(self) -> Optional[str]:
        """获取下一个可用代理"""
        if not self.proxies:
            return None
        
        with self.lock:
            attempts = 0
            while attempts < len(self.proxies):
                proxy = self.proxies[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.proxies)
                
                if proxy not in self.failed_proxies:
                    return proxy
                attempts += 1
        
        return None
    
    def mark_proxy_failed(self, proxy: str):
        """标记代理失败"""
        self.failed_proxies.add(proxy)

class AdaptiveRateLimiter:
    """自适应速率限制器 - 优化版本"""
    
    def __init__(self, initial_rps: float = 10.0, max_rps: float = 50.0, min_rps: float = 1.0):
        self.rps = initial_rps
        self.max_rps = max_rps
        self.min_rps = min_rps
        self.last_request_time = 0
        self.error_count = 0
        self.success_count = 0
        self.adjustment_interval = 20
        self.request_count = 0
        self.lock = threading.Lock()
        self.request_times = deque(maxlen=100)  # 记录最近100个请求的时间
        self._semaphore_limit = int(max_rps * 2)  # 保存信号量限制
        self._semaphore = asyncio.Semaphore(self._semaphore_limit)
    
    async def acquire(self):
        """获取请求许可 - 优化版本"""
        # 先获取信号量，防止突发大量请求
        async with self._semaphore:
            with self.lock:
                current_time = time.time()
                self.request_times.append(current_time)
                
                # 计算当前实际RPS
                if len(self.request_times) >= 2:
                    time_span = self.request_times[-1] - self.request_times[0]
                    if time_span > 0:
                        current_rps = (len(self.request_times) - 1) / time_span
                        # 如果当前RPS超过限制，需要等待
                        if current_rps > self.rps:
                            sleep_time = (len(self.request_times) / self.rps) - time_span
                            if sleep_time > 0:
                                # 记录需要等待的时间
                                required_sleep = sleep_time
                            else:
                                required_sleep = 0
                        else:
                            required_sleep = 0
                    else:
                        required_sleep = 0
                else:
                    required_sleep = 0
                
                self.last_request_time = time.time()
            
            # 在信号量上下文之外等待，避免信号量长时间被占用
            if required_sleep > 0:
                await asyncio.sleep(required_sleep)
    
    def record_success(self):
        """记录成功请求"""
        self.success_count += 1
        self._adjust_rate()
    
    def record_error(self):
        """记录错误请求"""
        self.error_count += 1
        self._adjust_rate()
    
    def _adjust_rate(self):
        """调整请求速率 - 优化版本"""
        self.request_count += 1
        
        if self.request_count % self.adjustment_interval == 0:
            total_requests = self.success_count + self.error_count
            if total_requests > 0:
                success_rate = self.success_count / total_requests
                
                # 更保守的动态调整速率
                if success_rate > 0.95:  # 成功率很高，适度增加
                    self.rps = min(self.rps * 1.1, self.max_rps)
                elif success_rate > 0.85:  # 成功率较高，小幅增加
                    self.rps = min(self.rps * 1.05, self.max_rps)
                elif success_rate < 0.5:  # 成功率低，大幅降低
                    self.rps = max(self.rps * 0.8, self.min_rps)
                elif success_rate < 0.7:  # 成功率较低，适度降低
                    self.rps = max(self.rps * 0.9, self.min_rps)
                
                # 更新信号量限制
                new_limit = int(self.rps * 2)
                if new_limit != self._semaphore_limit:
                    self._semaphore_limit = new_limit
                    self._semaphore = asyncio.Semaphore(new_limit)
                
                # 重置计数器
                self.success_count = 0
                self.error_count = 0
                
                logger.debug(f"调整请求速率: {self.rps:.1f} RPS")

class ResourceMonitor:
    """资源监控器 - 监控系统资源并自动调整并发数"""
    
    def __init__(self, scanner, memory_threshold=80.0, cpu_threshold=70.0, check_interval=5):
        self.scanner = scanner
        self.memory_threshold = memory_threshold
        self.cpu_threshold = cpu_threshold
        self.check_interval = check_interval
        self.running = False
        self.monitor_task = None
        self.original_concurrency = None
        self.lock = threading.Lock()
    
    def start(self):
        """启动资源监控"""
        if not self.running:
            self.running = True
            self.original_concurrency = self.scanner.max_concurrency
            self.monitor_task = asyncio.create_task(self._monitor_loop())
            logger.info(f"资源监控已启动，内存阈值: {self.memory_threshold}%, CPU阈值: {self.cpu_threshold}%")
    
    async def stop(self):
        """停止资源监控"""
        if self.running:
            self.running = False
            if self.monitor_task:
                self.monitor_task.cancel()
                try:
                    await self.monitor_task
                except asyncio.CancelledError:
                    pass
            # 恢复原始并发设置
            if hasattr(self.scanner, 'max_concurrency') and self.original_concurrency is not None:
                with self.lock:
                    self.scanner.max_concurrency = self.original_concurrency
            logger.info("资源监控已停止")
    
    async def _monitor_loop(self):
        """监控循环"""
        while self.running:
            try:
                await self._check_resources()
            except Exception as e:
                logger.error(f"资源监控错误: {str(e)}")
            
            # 等待下一次检查
            for _ in range(self.check_interval):
                if not self.running:
                    break
                await asyncio.sleep(1)
    
    async def _check_resources(self):
        """检查系统资源使用情况"""
        try:
            # 导入psutil库（仅在需要时导入）
            import psutil
            
            # 获取当前进程
            process = psutil.Process()
            
            # 检查内存使用
            with process.oneshot():
                memory_info = process.memory_info()
                # 计算内存使用率（进程内存 / 系统总内存）
                system_memory = psutil.virtual_memory().total
                memory_percent = (memory_info.rss / system_memory) * 100 if system_memory > 0 else 0
                
                # 检查CPU使用
                cpu_percent = process.cpu_percent(interval=0.1)
            
            # 调整并发数
            await self._adjust_concurrency(memory_percent, cpu_percent)
            
        except ImportError:
            logger.warning("psutil库未安装，无法进行资源监控")
            await self.stop()
        except Exception as e:
            logger.error(f"资源检查错误: {str(e)}")
    
    async def _adjust_concurrency(self, memory_percent, cpu_percent):
        """根据资源使用情况调整并发数"""
        with self.lock:
            if hasattr(self.scanner, 'max_concurrency'):
                current_concurrency = self.scanner.max_concurrency
                new_concurrency = current_concurrency
                
                # 如果内存或CPU使用率超过阈值，降低并发
                if memory_percent > self.memory_threshold or cpu_percent > self.cpu_threshold:
                    # 降低20%的并发数，但不低于1
                    new_concurrency = max(1, int(current_concurrency * 0.8))
                    if new_concurrency != current_concurrency:
                        self.scanner.max_concurrency = new_concurrency
                        logger.info(f"资源使用率过高，降低并发数: {current_concurrency} → {new_concurrency} (内存: {memory_percent:.1f}%, CPU: {cpu_percent:.1f}%)")
                
                # 如果资源使用率较低且并发数低于原始值，逐渐恢复
                elif (memory_percent < self.memory_threshold * 0.8 and 
                      cpu_percent < self.cpu_threshold * 0.8 and 
                      current_concurrency < self.original_concurrency):
                    # 增加10%的并发数，但不超过原始值
                    new_concurrency = min(self.original_concurrency, int(current_concurrency * 1.1))
                    if new_concurrency != current_concurrency:
                        self.scanner.max_concurrency = new_concurrency
                        logger.info(f"资源充足，增加并发数: {current_concurrency} → {new_concurrency} (内存: {memory_percent:.1f}%, CPU: {cpu_percent:.1f}%)")

class ResultAnalyzer:
    """结果分析器"""
    
    def __init__(self):
        self.risk_patterns = {
            'critical': [
                # 敏感配置文件
                r'\.env', r'config\.', r'\.htaccess', r'web\.config',
                r'passwd', r'shadow', r'private', r'secret',
                
                # 数据库相关
                r'dump\.sql', r'backup\.sql', r'database',
                
                # 管理后台
                r'phpmyadmin', r'adminer', r'webmin',
                
                # 密钥文件
                r'\.pem$', r'\.key$', r'id_rsa', r'id_dsa'
            ],
            'high': [
                r'admin', r'administrator', r'root', r'login',
                r'panel', r'dashboard', r'control', r'console',
                r'backup', r'back', r'old', r'archive',
                r'\.git/', r'\.svn/', r'\.hg/'
            ],
            'medium': [
                r'upload', r'uploads', r'file', r'files',
                r'test', r'dev', r'staging', r'debug',
                r'api', r'webservice', r'endpoint',
                r'log', r'logs', r'tmp', r'temp'
            ],
            'low': [
                r'images', r'img', r'css', r'js', 
                r'assets', r'static', r'public',
                r'docs', r'document', r'help', r'about'
            ]
        }
    
    def assess_risk(self, url: str, status: int, content_length: int) -> str:
        """评估风险等级"""
        url_lower = url.lower()
        
        # 状态码风险评估
        if status == 403:
            return 'high'  # 禁止访问通常意味着资源存在但受保护
        elif status == 401:
            return 'medium'  # 需要认证
        
        # 基于URL模式的风险评估
        for level, patterns in self.risk_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    return level
        
        # 基于内容长度的启发式评估
        if status == 200:
            if content_length == 0:
                return 'low'
            elif content_length > 1000000:  # 大于1MB的文件
                return 'medium'
        
        return 'info'
    
    def cluster_results(self, results: List[ScanResult]) -> Dict[str, List[ScanResult]]:
        """聚类扫描结果"""
        clusters = {
            'critical': [], 'high': [], 'medium': [], 
            'low': [], 'info': [], 'redirects': []
        }
        
        for result in results:
            # 重定向单独分类
            if 300 <= result.status < 400:
                clusters['redirects'].append(result)
            else:
                risk_level = self.assess_risk(
                    result.url, result.status, result.content_length
                )
                result.risk_level = risk_level
                clusters[risk_level].append(result)
        
        return clusters

class ReportGenerator:
    """报告生成器"""
    
    def __init__(self):
        pass
    
    def generate_json_report(self, results: List[ScanResult], stats: Dict, output_file: str):
        """生成JSON格式报告"""
        # 聚类结果
        analyzer = ResultAnalyzer()
        clusters = analyzer.cluster_results(results)
        
        report = {
            'scan_info': {
                'target': stats.get('target', ''),
                'start_time': stats.get('start_time', 0),
                'duration': stats.get('duration', 0),
                'total_requests': stats.get('requests_sent', 0),
                'failed_requests': stats.get('requests_failed', 0),
                'meaningful_responses': stats.get('meaningful_responses', 0),
                'requests_per_second': stats.get('requests_per_second', 0)
            },
            'results_by_risk': {},
            'all_results': [r.to_dict() for r in results]
        }
        
        # 按风险等级组织结果
        for risk_level, risk_results in clusters.items():
            report['results_by_risk'][risk_level] = [r.to_dict() for r in risk_results]
        
        # 输出到文件
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report
    
    def generate_csv_report(self, results: List[ScanResult], output_file: str):
        """生成CSV格式报告"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # 写入标题行
            writer.writerow(['URL', 'Status', 'Content Length', 'Content Type', 
                           'Title', 'Redirect URL', 'Response Time', 'Risk Level'])
            
            # 写入数据行
            for result in results:
                writer.writerow([
                    result.url, result.status, result.content_length, 
                    result.content_type, result.title, result.redirect_url,
                    result.response_time, result.risk_level
                ])
    
    def generate_html_report(self, results: List[ScanResult], stats: Dict, output_file: str):
        """生成HTML格式报告"""
        # 聚类结果
        analyzer = ResultAnalyzer()
        clusters = analyzer.cluster_results(results)
        
        # HTML模板
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>目录扫描报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .critical { background-color: #ffebee; }
        .high { background-color: #fff8e1; }
        .medium { background-color: #e8f5e8; }
        .low { background-color: #e3f2fd; }
        .info { background-color: #f5f5f5; }
        .redirects { background-color: #e0f2f1; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .risk-count { display: inline-block; padding: 5px 10px; margin-right: 10px; border-radius: 3px; color: white; }
        .critical-count { background-color: #f44336; }
        .high-count { background-color: #ff9800; }
        .medium-count { background-color: #4caf50; }
        .low-count { background-color: #2196f3; }
        .info-count { background-color: #9e9e9e; }
        .redirects-count { background-color: #009688; }
    </style>
</head>
<body>
    <h1>目录扫描报告</h1>
    
    <div class="summary">
        <h2>扫描摘要</h2>
        <p><strong>目标URL:</strong> {target}</p>
        <p><strong>扫描时长:</strong> {duration:.2f} 秒</p>
        <p><strong>总请求数:</strong> {total_requests}</p>
        <p><strong>成功响应:</strong> {meaningful_responses}</p>
        <p><strong>请求速率:</strong> {requests_per_second:.1f} 请求/秒</p>
        
        <h3>按风险等级分类</h3>
        <div>
            <span class="risk-count critical-count">严重: {critical_count}</span>
            <span class="risk-count high-count">高风险: {high_count}</span>
            <span class="risk-count medium-count">中风险: {medium_count}</span>
            <span class="risk-count low-count">低风险: {low_count}</span>
            <span class="risk-count info-count">信息: {info_count}</span>
            <span class="risk-count redirects-count">重定向: {redirects_count}</span>
        </div>
    </div>
    
    {results_sections}
    
    <script>
        // 添加排序功能
        function sortTable(n) {
            var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
            table = document.getElementById("resultsTable");
            switching = true;
            dir = "asc";
            while (switching) {
                switching = false;
                rows = table.rows;
                for (i = 1; i < (rows.length - 1); i++) {
                    shouldSwitch = false;
                    x = rows[i].getElementsByTagName("TD")[n];
                    y = rows[i + 1].getElementsByTagName("TD")[n];
                    if (dir == "asc") {
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                            shouldSwitch = true;
                            break;
                        }
                    } else if (dir == "desc") {
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                            shouldSwitch = true;
                            break;
                        }
                    }
                }
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                } else {
                    if (switchcount == 0 && dir == "asc") {
                        dir = "desc";
                        switching = true;
                    }
                }
            }
        }
    </script>
</body>
</html>
        """
        
        # 生成结果部分
        results_sections = ""
        for risk_level in ['critical', 'high', 'medium', 'low', 'info', 'redirects']:
            risk_results = clusters.get(risk_level, [])
            if not risk_results:
                continue
                
            level_name = {
                'critical': '严重',
                'high': '高风险',
                'medium': '中风险',
                'low': '低风险',
                'info': '信息',
                'redirects': '重定向'
            }[risk_level]
            
            results_sections += f"""
    <h2>{level_name} ({len(risk_results)} 个)</h2>
    <table id="resultsTable">
        <tr>
            <th onclick="sortTable(0)">URL</th>
            <th onclick="sortTable(1)">状态码</th>
            <th onclick="sortTable(2)">内容长度</th>
            <th onclick="sortTable(3)">内容类型</th>
            <th onclick="sortTable(4)">标题</th>
            <th onclick="sortTable(5)">响应时间(ms)</th>
        </tr>
"""
            
            for result in risk_results:
                results_sections += f"""
        <tr class="{risk_level}">
            <td><a href="{result.url}" target="_blank">{result.url}</a></td>
            <td>{result.status}</td>
            <td>{result.content_length}</td>
            <td>{result.content_type}</td>
            <td>{result.title}</td>
            <td>{result.response_time:.2f}</td>
        </tr>
"""
            
            results_sections += "\n    </table>\n"
        
        # 填充模板
        html_content = html_template.format(
            target=stats.get('target', ''),
            duration=stats.get('duration', 0),
            total_requests=stats.get('requests_sent', 0),
            meaningful_responses=stats.get('meaningful_responses', 0),
            requests_per_second=stats.get('requests_per_second', 0),
            critical_count=len(clusters.get('critical', [])),
            high_count=len(clusters.get('high', [])),
            medium_count=len(clusters.get('medium', [])),
            low_count=len(clusters.get('low', [])),
            info_count=len(clusters.get('info', [])),
            redirects_count=len(clusters.get('redirects', [])),
            results_sections=results_sections
        )
        
        # 输出到文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

class AdvancedDirectoryScanner:
    """高级目录扫描器 - Windows优化版本"""
    
    def __init__(self, 
                 base_url: str,
                 wordlist: List[str] = None,
                 max_concurrency: int = 50,
                 timeout: int = 10,
                 user_agent: str = None,
                 output_timeout: int = 10):
        
        self.base_url = base_url.rstrip('/') + '/'
        self.wordlist = wordlist or []
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (compatible; AdvancedDirScanner/1.0)"
        self.output_timeout = output_timeout  # 无输出超时时间（秒）
        self.last_output_time = time.time()  # 最后一次输出时间
        self.monitor_task = None  # 监控任务
        
        # 初始化组件
        self.response_analyzer = SmartResponseAnalyzer()
        self.auth_handler = AuthHandler()
        self.proxy_manager = ProxyManager()
        self.rate_limiter = AdaptiveRateLimiter()
        self.result_analyzer = ResultAnalyzer()
        self.report_generator = ReportGenerator()
        
        # 扫描状态
        self.scanned_urls = set()
        self.found_results = []
        self.session = None
        self.lock = threading.Lock()
        self.stop_event = asyncio.Event()
        
        # 统计信息
        self.stats = {
            'requests_sent': 0,
            'requests_failed': 0,
            'meaningful_responses': 0,
            'start_time': time.time()
        }
        
        # Windows兼容的信号处理
        if sys.platform == 'win32' and HAS_WIN32:
            # Windows控制台处理
            win32api.SetConsoleCtrlHandler(self._windows_ctrl_handler, True)
        elif not HAS_WIN32:
            # Unix信号处理
            import signal
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
    
    def _windows_ctrl_handler(self, event_type):
        """Windows控制台事件处理器"""
        if event_type in [0, 2]:  # CTRL_C_EVENT, CTRL_CLOSE_EVENT
            print("\n接收到中断信号，正在停止扫描...")
            asyncio.create_task(self._stop_scan())
            return True
        return False
    
    def _handle_signal(self, signum, frame):
        """Unix信号处理器"""
        print(f"\n接收到信号 {signum}，正在停止扫描...")
        asyncio.create_task(self._stop_scan())
    
    async def _stop_scan(self):
        """停止扫描"""
        self.stop_event.set()
        # 取消监控任务
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        # 取消所有活跃的扫描任务
        if hasattr(self, 'active_tasks') and self.active_tasks:
            for task in self.active_tasks.copy():
                if not task.done():
                    task.cancel()
        # 关闭会话
        if self.session:
            await self.session.close()
            self.session = None
    
    async def initialize(self):
        """初始化扫描器 - Windows优化版本"""
        try:
            logger.info(f"正在初始化扫描器，目标: {self.base_url}")
            
            # 创建优化的TCPConnector
            connector = aiohttp.TCPConnector(
                limit=self.max_concurrency, 
                ssl=False,  # 使用ssl替代verify_ssl
                use_dns_cache=True,
                ttl_dns_cache=300,
                # Windows优化参数
                family=0,  # 支持IPv4和IPv6
                force_close=True,  # 完成后强制关闭连接
                enable_cleanup_closed=True,  # 启用连接清理
                limit_per_host=self.max_concurrency,  # 每主机连接限制
                fingerprint=None,  # 不发送SSL指纹
            )
            
            # 优化的超时设置
            timeout = aiohttp.ClientTimeout(
                total=self.timeout,
                connect=10,  # 连接超时
                sock_connect=15,  # Socket连接超时
                sock_read=30  # Socket读取超时
            )
            
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': self.user_agent},
                raise_for_status=False,  # 不自动抛出HTTP错误
                cookie_jar=aiohttp.DummyCookieJar()  # 使用内存Cookie存储
            )
            
            # 测试基础URL是否可达
            logger.info("测试目标服务器连接...")
            try:
                async with self.session.get(self.base_url, allow_redirects=False, timeout=5) as test_resp:
                    logger.info(f"目标服务器响应: {test_resp.status}")
                    if test_resp.status >= 500:
                        logger.warning(f"服务器返回错误状态码: {test_resp.status}")
            except Exception as e:
                logger.error(f"无法连接到目标服务器: {e}")
                raise
            
            # 建立404基线
            logger.info("建立404响应基线...")
            if not await self.response_analyzer.establish_baseline(self.base_url, self.session):
                logger.warning("无法建立可靠的404基线，扫描准确性可能受影响")
            
            # 创建并启动资源监控器
            self.resource_monitor = ResourceMonitor(
                scanner=self,
                memory_threshold=80.0,
                cpu_threshold=70.0,
                check_interval=5
            )
            self.resource_monitor.start()
            
            # 启动输出监控任务
            self.monitor_task = asyncio.create_task(self._monitor_output())
            
            logger.info("扫描器初始化完成")
                
        except Exception as e:
            logger.error(f"初始化失败: {e}")
            raise
    
    def _calculate_optimal_concurrency(self) -> int:
        """根据系统资源和字典大小计算最优并发数"""
        # 基础并发数
        base_concurrency = self.max_concurrency
        
        # 根据字典大小调整
        wordlist_size = len(self.wordlist)
        if wordlist_size > 5000:
            # 超大字典，大幅降低并发
            return min(base_concurrency, 30)
        elif wordlist_size > 1000:
            # 大字典，适度降低并发
            return min(base_concurrency, 50)
        elif wordlist_size < 100:
            # 小字典，可以提高并发
            return min(base_concurrency, 100)
        
        return base_concurrency

    async def scan_url(self, path: str) -> Optional[ScanResult]:
        """扫描单个URL"""
        logger.debug(f"scan_url开始: {path}")
        
        if self.stop_event.is_set():
            logger.debug(f"扫描停止，跳过URL: {path}")
            return None
            
        url = urljoin(self.base_url, path)
        logger.debug(f"构建URL: {url}")
        
        # 避免重复扫描
        with self.lock:
            if url in self.scanned_urls:
                logger.debug(f"URL已扫描，跳过: {url}")
                return None
            self.scanned_urls.add(url)
            logger.debug(f"添加到已扫描集合: {url}")
        
        # 速率限制
        logger.debug(f"等待速率限制: {url}")
        await self.rate_limiter.acquire()
        logger.debug(f"获取速率限制令牌: {url}")
        
        result = None
        content = None
        success = False
        
        try:
            self.stats['requests_sent'] += 1
            start_time = time.time()
            
            # 准备请求参数
            kwargs = {
                'allow_redirects': False,
                'headers': self.auth_handler.get_headers(),
                'timeout': aiohttp.ClientTimeout(total=30)  # 添加30秒超时
            }
            logger.debug(f"请求参数准备完成: {url}")
            
            # 添加Cookies
            cookies = self.auth_handler.get_cookies()
            if cookies:
                kwargs['cookies'] = cookies
                logger.debug(f"添加Cookies: {url}")
            
            # 添加代理
            proxy = self.proxy_manager.get_next_proxy()
            if proxy:
                kwargs['proxy'] = proxy
                logger.debug(f"使用代理: {proxy} 访问 {url}")
            
            # 发送请求
            logger.debug(f"开始发送请求: {url}")
            async with self.session.get(url, **kwargs) as response:
                logger.debug(f"收到响应: {url} 状态码: {response.status}")
                response_time = time.time() - start_time
                logger.debug(f"响应时间: {response_time:.3f}秒 {url}")
                
                logger.debug(f"开始读取响应内容: {url}")
                content = await response.text()
                logger.debug(f"响应内容读取完成，长度: {len(content)} {url}")
                
                # 创建结果对象
                result = ScanResult(
                    url=url,
                    status=response.status,
                    content_length=len(content),
                    content_type=response.headers.get('Content-Type', ''),
                    redirect_url=response.headers.get('Location', ''),
                    headers=dict(response.headers),
                    response_time=response_time
                )
                
                # 提取页面标题
                title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
                if title_match:
                    result.title = title_match.group(1).strip()[:100]
            
            # 请求成功完成
            success = True
            
            # 分析响应是否有意义
            is_meaningful = False
            if result and content:
                # 详细记录响应信息用于调试
                logger.debug(f"响应调试信息 - URL: {url}, 状态码: {result.status}, 内容长度: {result.content_length}, 重定向URL: {result.redirect_url}")
                
                # 特别为robots.txt添加额外调试
                if "robots.txt" in url:
                    logger.debug(f"===== ROBOTS.TXT 特殊处理 ==== URL: {url}, 状态码: {result.status}, 内容预览: {content[:50]}")
                    # 强制标记robots.txt为有效响应如果状态码为200
                    if result.status == 200:
                        logger.debug(f"强制标记robots.txt为有效响应，状态码为200")
                        is_meaningful = True
                
                # 检查响应指纹
                current_fp = self.response_analyzer._create_fingerprint(content, result.headers or {})
                logger.debug(f"响应指纹: {current_fp}")
                
                # 检查长度相似性
                if self.response_analyzer.baseline_404:
                    baseline_len = self.response_analyzer.baseline_404.get('length', 0)
                    if baseline_len > 0:
                        similarity = min(baseline_len, result.content_length) / max(baseline_len, result.content_length)
                        logger.debug(f"长度相似性: {similarity:.2f}, 基线长度: {baseline_len}")
                
                # 如果不是强制标记的robots.txt，再使用常规判断
                if not is_meaningful:
                    is_meaningful = self.response_analyzer.is_meaningful_response(result, content)
                
                # 额外检查：状态码为200的响应应该被视为有效
                if result.status == 200:
                    logger.debug(f"状态码为200，强制视为有效响应: {url}")
                    is_meaningful = True
                
            if is_meaningful:
                self.stats['meaningful_responses'] += 1
                logger.debug(f"发现有效响应: {url} - 状态码: {result.status}, 长度: {result.content_length}")
                return result
            else:
                logger.debug(f"无效响应: {url} - 状态码: {result.status}, 长度: {result.content_length}")
                return None
                
        except asyncio.CancelledError:
            logger.debug(f"请求被取消: {url}")
            raise
        except aiohttp.ClientError as e:
            # 区分不同类型的客户端错误
            if isinstance(e, aiohttp.ClientConnectorError):
                logger.debug(f"连接错误 {url}: {str(e)}")
            elif isinstance(e, aiohttp.ClientOSError):
                logger.debug(f"操作系统错误 {url}: {str(e)}")
            else:
                logger.debug(f"请求错误 {url}: {str(e)}")
            self.stats['requests_failed'] += 1
            
            # 处理代理失败
            if 'proxy' in kwargs:
                self.proxy_manager.record_failure(kwargs['proxy'])
            return None
        except asyncio.TimeoutError:
            logger.debug(f"请求超时 {url}")
            self.stats['requests_failed'] += 1
            return None
        except Exception as e:
            logger.error(f"未知错误 {url}: {str(e)}")
            self.stats['requests_failed'] += 1
            return None
        finally:
            # 记录成功或失败
            if success:
                self.rate_limiter.record_success()
            else:
                self.rate_limiter.record_error()
            logger.debug(f"完成处理: {url}")
    
    async def run_scan(self) -> List[ScanResult]:
        """运行扫描 - 优化版本"""
        if not self.session:
            await self.initialize()
        
        logger.info(f"开始扫描 {self.base_url}")
        logger.info(f"字典大小: {len(self.wordlist)}")
        logger.info(f"并发数: {self.max_concurrency}")
        
        # 检查字典是否为空
        if not self.wordlist:
            logger.warning("字典为空，没有路径可扫描")
            return []
        
        # 自适应并发控制
        effective_concurrency = self._calculate_optimal_concurrency()
        semaphore = asyncio.Semaphore(effective_concurrency)
        logger.info(f"使用最优并发数: {effective_concurrency}")
        
        async def controlled_scan(path):
            """控制并发的扫描函数"""
            logger.debug(f"开始扫描路径: {path}")
            if self.stop_event.is_set():
                logger.debug(f"扫描停止，跳过路径: {path}")
                return None
            
            try:
                async with semaphore:
                    # 再次检查，避免在等待信号量期间已经触发停止
                    if self.stop_event.is_set():
                        logger.debug(f"扫描停止，跳过路径: {path}")
                        return None
                    # 每次执行前更新最后输出时间，防止监控超时
                    self.last_output_time = time.time()
                    logger.debug(f"获取信号量，开始请求: {path}")
                    result = await self.scan_url(path)
                    logger.debug(f"扫描完成: {path}, 结果: {result is not None}")
                    return result
            except asyncio.CancelledError:
                logger.debug(f"扫描任务被取消: {path}")
                self.last_output_time = time.time()
                raise
            except Exception as e:
                logger.error(f"扫描路径时出错 {path}: {str(e)}")
                self.last_output_time = time.time()
                return None
        
        # 根据字典大小动态调整批次大小
        wordlist_size = len(self.wordlist)
        if wordlist_size > 10000:
            batch_size = 200  # 超大字典使用较大批次
        elif wordlist_size > 1000:
            batch_size = 100  # 大字典使用中等批次
        else:
            batch_size = 50   # 小字典使用较小批次
        
        total_processed = 0
        self.active_tasks = set()  # 将active_tasks作为实例属性，方便_stop_scan访问
        active_tasks = self.active_tasks
        max_active_tasks = min(effective_concurrency * 2, 200)  # 限制最大活跃任务数
        
        logger.info(f"使用批次大小: {batch_size}, 最大活跃任务: {max_active_tasks}")
        
        # 使用迭代器处理字典，减少内存占用
        wordlist_iter = iter(self.wordlist)
        
        logger.debug(f"开始扫描循环，字典大小: {len(self.wordlist)}")
        
        try:
            iteration_count = 0
            while not self.stop_event.is_set() and iteration_count < 100:  # 限制最大迭代次数防止无限循环
                iteration_count += 1
                logger.debug(f"扫描循环迭代 {iteration_count}")
                # 清理已完成的任务
                logger.debug(f"当前活跃任务数量: {len(active_tasks)}")
                done_tasks = {task for task in active_tasks if task.done()}
                active_tasks -= done_tasks
                logger.debug(f"完成任务数量: {len(done_tasks)}")
                
                # 处理已完成的任务结果
                for task in done_tasks:
                    try:
                        result = task.result()
                        if isinstance(result, ScanResult) and result:
                            self.found_results.append(result)
                            self._print_result(result)
                    except Exception as e:
                        logger.debug(f"任务异常: {e}")
                    finally:
                        total_processed += 1
                        
                        # 定期更新进度
                        if total_processed % (batch_size * 2) == 0:
                            self.last_output_time = time.time()
                            progress = min(total_processed / wordlist_size * 100, 100)
                            logger.info(f"进度: 已处理 {total_processed}/{wordlist_size} 个路径 ({progress:.1f}%)")
                
                # 动态添加新任务，控制任务数量
                logger.debug(f"准备添加新任务，活跃任务数: {len(active_tasks)}, 最大活跃任务: {max_active_tasks}")
                new_tasks_added = 0
                while not self.stop_event.is_set() and len(active_tasks) < max_active_tasks:
                    try:
                        path = next(wordlist_iter)
                        logger.debug(f"添加扫描任务: {path}")
                        task = asyncio.create_task(controlled_scan(path))
                        active_tasks.add(task)
                        new_tasks_added += 1
                    except StopIteration:
                        # 字典迭代完成
                        logger.debug("字典迭代完成，无更多路径")
                        wordlist_iter = None  # 标记迭代器已耗尽
                        break
                
                # 如果没有更多任务，等待所有任务完成
                if not active_tasks and wordlist_iter is None:
                    logger.debug("所有任务完成，准备退出扫描循环")
                    break
                
                # 短暂休息，避免CPU过载
                sleep_time = 0.05 if wordlist_size > 1000 else 0.01
                
                # 为每个迭代更新最后输出时间，防止输出监控超时
                self.last_output_time = time.time()
                logger.debug(f"迭代 {iteration_count} 完成，等待 {sleep_time} 秒")
                
                # 限制单次休息时间，确保检查stop_event
                await asyncio.sleep(min(sleep_time, 1.0))
                
                # 定期检查资源使用情况（即使没有外部监控）
                if total_processed % 500 == 0 and wordlist_size > 1000:
                    # 强制垃圾回收
                    import gc
                    gc.collect()
                    logger.debug(f"已处理 {total_processed} 个路径，强制垃圾回收")
            
            # 等待剩余任务完成
            if active_tasks:
                logger.info("等待剩余任务完成...")
                await asyncio.gather(*active_tasks, return_exceptions=True)
                
        except asyncio.CancelledError:
            logger.info("扫描被取消")
        except Exception as e:
            logger.error(f"扫描过程中发生异常: {e}")
        finally:
            # 确保更新最后输出时间
            self.last_output_time = time.time()
            # 清空活跃任务列表
            if hasattr(self, 'active_tasks'):
                self.active_tasks.clear()
            logger.info(f"扫描完成，共处理 {total_processed} 个路径")
        
        return self.found_results
    
    async def run_scan_with_timeout(self, timeout=300):
        """带超时的扫描运行"""
        try:
            # 创建带超时的扫描任务
            scan_task = asyncio.create_task(self.run_scan())
            done, pending = await asyncio.wait(
                [scan_task], 
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED
            )
            
            if pending:
                print(f"\n扫描超时（{timeout}秒），正在停止...")
                self.stop_event.set()
                scan_task.cancel()
                try:
                    await scan_task
                except asyncio.CancelledError:
                    pass
            
            return self.found_results
            
        except asyncio.TimeoutError:
            print(f"\n操作超时（{timeout}秒）")
            self.stop_event.set()
            return self.found_results
        except Exception as e:
            print(f"\n扫描错误: {e}")
            return self.found_results
    
    async def _monitor_output(self):
        """监控输出，超过指定时间无输出则退出"""
        try:
            while not self.stop_event.is_set():
                await asyncio.sleep(1)  # 每秒检查一次
                
                # 检查是否超过超时时间
                if time.time() - self.last_output_time > self.output_timeout:
                    logger.warning(f"超过{self.output_timeout}秒无输出，正在停止扫描...")
                    await self._stop_scan()
                    break
        except asyncio.CancelledError:
            pass
    
    def _print_result(self, result: ScanResult):
        """打印扫描结果"""
        # 更新最后输出时间
        self.last_output_time = time.time()
        
        # 使用ANSI颜色代码
        status_colors = {
            200: '\033[92m',  # 绿色
            301: '\033[96m',  # 青色
            302: '\033[96m',  # 青色
            403: '\033[93m',  # 黄色
            401: '\033[93m',  # 黄色
            500: '\033[91m'   # 红色
        }
        
        risk_colors = {
            'critical': '\033[91m',  # 红色
            'high': '\033[93m',      # 黄色
            'medium': '\033[92m',    # 绿色
            'low': '\033[94m',       # 蓝色
            'info': '\033[0m',       # 默认
            'redirects': '\033[96m'   # 青色
        }
        
        reset = '\033[0m'
        
        # 选择颜色
        status_color = status_colors.get(result.status, '\033[0m')
        risk_color = risk_colors.get(result.risk_level, '\033[0m')
        
        # 格式化输出
        status_str = f"{status_color}{result.status}{reset}"
        risk_str = f"{risk_color}[{result.risk_level.upper()}]{reset}"
        length_str = f"{result.content_length}" if result.content_length > 0 else "0"
        
        output = f"{risk_str} [{status_str}] {result.url}"
        if result.redirect_url:
            output += f" -> {result.redirect_url}"
        if result.title:
            output += f" [{result.title[:50]}]"
        output += f" ({length_str} bytes, {result.response_time:.2f}s)"
        
        print(output)
    
    def generate_report(self, output_file: str = None, format: str = 'json'):
        """生成扫描报告"""
        try:
            # 确保输出目录存在
            if output_file:
                output_dir = os.path.dirname(output_file)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
            
            # 计算统计信息
            total_time = time.time() - self.stats['start_time']
            req_per_sec = self.stats['requests_sent'] / total_time if total_time > 0 else 0
            
            # 更新统计信息
            self.stats.update({
                'target': self.base_url,
                'duration': total_time,
                'requests_per_second': req_per_sec
            })
            
            # 根据格式生成报告
            if format.lower() == 'json':
                result = self.report_generator.generate_json_report(self.found_results, self.stats, output_file)
                logger.info(f"JSON报告已保存到: {output_file}")
                return result
            elif format.lower() == 'csv':
                result = self.report_generator.generate_csv_report(self.found_results, output_file)
                logger.info(f"CSV报告已保存到: {output_file}")
                return result
            elif format.lower() == 'html':
                result = self.report_generator.generate_html_report(self.found_results, self.stats, output_file)
                # 修复HTML模板中的字体错误
                if isinstance(result, str):
                    result = result.replace("' font-family'", "font-family")
                logger.info(f"HTML报告已保存到: {output_file}")
                return result
            else:
                logger.error(f"不支持的报告格式: {format}")
                return None
        except Exception as e:
            logger.error(f"生成报告失败: {str(e)}")
            raise
    
    def print_summary(self):
        """打印扫描摘要"""
        # 更新最后输出时间
        self.last_output_time = time.time()
        
        # 聚类结果
        clusters = self.result_analyzer.cluster_results(self.found_results)
        
        # 计算统计信息
        total_time = time.time() - self.stats['start_time']
        req_per_sec = self.stats['requests_sent'] / total_time if total_time > 0 else 0
        
        print("\n" + "="*60)
        print("扫描摘要")
        print("="*60)
        print(f"目标URL: {self.base_url}")
        print(f"扫描时长: {total_time:.2f} 秒")
        print(f"总请求数: {self.stats['requests_sent']}")
        print(f"成功响应: {self.stats['meaningful_responses']}")
        print(f"请求速率: {req_per_sec:.1f} 请求/秒")
        print("\n按风险等级分类:")
        for risk_level in ['critical', 'high', 'medium', 'low', 'info', 'redirects']:
            count = len(clusters.get(risk_level, []))
            if count > 0:
                print(f"  {risk_level.upper()}: {count} 个")
    
    async def close(self):
        """关闭扫描器 - 资源清理"""
        # 停止资源监控器
        if hasattr(self, 'resource_monitor') and self.resource_monitor:
            try:
                await self.resource_monitor.stop()
            except Exception as e:
                logger.error(f"停止资源监控器失败: {e}")
        
        # 停止监控任务
        if hasattr(self, 'monitor_task') and self.monitor_task:
            try:
                self.monitor_task.cancel()
                try:
                    await self.monitor_task
                except asyncio.CancelledError:
                    pass
            except Exception as e:
                logger.error(f"停止监控任务失败: {e}")
        
        # 关闭会话
        if hasattr(self, 'session') and self.session:
            try:
                await self.session.close()
            except Exception as e:
                logger.error(f"关闭会话失败: {e}")
        
        logger.info("扫描器已安全关闭")

def load_wordlist(file_path: str) -> List[str]:
    """从文件加载字典"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"加载字典文件失败: {e}")
        return []

def load_proxy_list(file_path: str) -> List[str]:
    """从文件加载代理列表"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"加载代理列表失败: {e}")
        return []

def main():
    """主函数 - Windows优化版本"""
    # 为Windows平台设置更保守的默认参数
    is_windows = sys.platform == 'win32'
    
    # Windows事件循环策略 - 使用Selector而非Proactor
    if is_windows:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # Windows特定优化
        try:
            import ctypes
            import ctypes.wintypes
            # 设置进程工作集大小
            ctypes.windll.kernel32.SetProcessWorkingSetSize(
                ctypes.wintypes.HANDLE(-1), -1, -1
            )
            # 禁用快速编辑模式，减少控制台暂停
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 128)
        except Exception as e:
            logger.debug(f"Windows优化应用失败: {e}")
        
        logger.info("Windows平台优化已应用")
    
    # 根据平台设置更合理的默认值
    default_threads = 10 if is_windows else 30
    default_rps = 5.0 if is_windows else 10.0
    default_max_rps = 20.0 if is_windows else 50.0
    
    parser = argparse.ArgumentParser(description='高级目录扫描工具 - Windows优化版')
    parser.add_argument('url', help='目标URL')
    parser.add_argument('-w', '--wordlist', help='字典文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'html'], 
                       default='json', help='输出格式')
    parser.add_argument('-t', '--threads', type=int, default=default_threads, 
                       help=f'并发线程数 (Windows默认: {default_threads}, 其他平台默认: 30)')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='请求超时时间')
    parser.add_argument('--user-agent', help='自定义User-Agent')
    parser.add_argument('--proxy', help='代理服务器')
    parser.add_argument('--proxy-list', help='代理列表文件')
    parser.add_argument('--auth', help='基本认证 (用户名:密码)')
    parser.add_argument('--cookie', help='Cookie字符串')
    parser.add_argument('--generate-wordlist', action='store_true', 
                       help='基于目标生成动态字典')
    parser.add_argument('--save-wordlist', help='保存生成的字典到文件')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    parser.add_argument('--rps', type=float, default=default_rps, 
                       help=f'初始每秒请求数 (Windows默认: {default_rps}, 其他平台默认: 10.0)')
    parser.add_argument('--max-rps', type=float, default=default_max_rps, 
                       help=f'最大每秒请求数 (Windows默认: {default_max_rps}, 其他平台默认: 50.0)')
    parser.add_argument('--min-rps', type=float, default=1.0, help='最小每秒请求数')
    parser.add_argument('--scan-timeout', type=int, default=300, help='总扫描超时时间（秒）')
    parser.add_argument('--output-timeout', type=int, default=10, help='无输出超时时间（秒）')
    parser.add_argument('--memory-threshold', type=int, default=80, 
                       help='内存使用率阈值，超过此值将降低并发 (默认: 80%)')
    parser.add_argument('--cpu-threshold', type=int, default=70, 
                       help='CPU使用率阈值，超过此值将降低并发 (默认: 70%)')
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 准备字典
    wordlist = []
    
    if args.wordlist and os.path.exists(args.wordlist):
        wordlist = load_wordlist(args.wordlist)
        logger.info(f"从文件加载字典: {len(wordlist)} 条目")
    
    if args.generate_wordlist or not args.wordlist:
        logger.info("生成动态字典...")
        generator = DynamicWordlistGenerator(args.url)
        dynamic_words = generator.generate_target_specific_words()
        logger.info(f"生成动态字典: {len(dynamic_words)} 条目")
        
        if args.save_wordlist:
            with open(args.save_wordlist, 'w', encoding='utf-8') as f:
                for word in dynamic_words:
                    f.write(f"{word}\n")
            logger.info(f"字典已保存到: {args.save_wordlist}")
        
        wordlist.extend(dynamic_words)
    
    # 去重
    wordlist = list(set(wordlist))
    
    if not wordlist:
        logger.error("没有可用的字典文件")
        return
    
    # 在Windows上对大字典做特殊处理
    if is_windows and len(wordlist) > 10000:
        logger.warning(f"Windows平台下使用大字典 ({len(wordlist)} 条目)，将启用分批处理和自动内存优化")
        # 为大字典降低默认并发
        if args.threads > default_threads * 2:
            logger.info(f"自动降低并发数从 {args.threads} 到 {default_threads * 2}")
            args.threads = default_threads * 2
    
    # 创建扫描器
    scanner = AdvancedDirectoryScanner(
        base_url=args.url,
        wordlist=wordlist,
        max_concurrency=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        output_timeout=args.output_timeout
    )
    
    # 配置速率限制 - Windows使用更保守的参数
    scanner.rate_limiter = AdaptiveRateLimiter(
        initial_rps=args.rps,
        max_rps=args.max_rps,
        min_rps=args.min_rps
    )
    
    # 配置认证
    if args.auth:
        username, password = args.auth.split(':', 1)
        scanner.auth_handler.set_basic_auth(username, password)
    
    if args.cookie:
        cookies = {}
        for item in args.cookie.split(';'):
            if '=' in item:
                key, value = item.strip().split('=', 1)
                cookies[key] = value
        scanner.auth_handler.set_cookies(cookies)
    
    # 配置代理
    if args.proxy:
        scanner.proxy_manager = ProxyManager([args.proxy])
    elif args.proxy_list:
        proxy_list = load_proxy_list(args.proxy_list)
        if proxy_list:
            scanner.proxy_manager = ProxyManager(proxy_list)
            logger.info(f"加载代理列表: {len(proxy_list)} 个代理")
    
    # 运行扫描
    try:
        results = asyncio.run(scanner.run_scan_with_timeout(args.scan_timeout))
        scanner.print_summary()
        
        # 生成报告
        if args.output:
            scanner.generate_report(args.output, args.format)
            logger.info(f"报告已保存到: {args.output}")
            
        # Windows平台提示
        if is_windows:
            logger.info("\n==== Windows平台使用提示 ====")
            logger.info("1. 对于大型扫描，建议分批处理字典文件")
            logger.info("2. 并发数建议不超过20，以避免系统资源问题")
            logger.info("3. 如遇性能问题，可尝试降低--rps参数值")
            logger.info("4. 使用--memory-threshold和--cpu-threshold调整资源监控敏感度")
    except KeyboardInterrupt:
        logger.info("扫描被用户中断")
    except asyncio.TimeoutError:
        logger.error("扫描超时")
    except (aiohttp.ClientError, ConnectionError) as e:
        logger.error(f"网络连接错误: {e}")
    except MemoryError:
        logger.error("内存不足错误！请尝试减小字典大小或降低并发数")
    except Exception as e:
        logger.error(f"扫描过程中发生错误: {e}")
        import traceback
        logger.debug(traceback.format_exc())
    finally:
        # 确保资源清理
        logger.info("扫描结束，清理资源...")
        # 尝试停止扫描器（如果还在运行）
        if scanner:
            try:
                asyncio.run(scanner._stop_scan())
            except:
                pass
        # 安全关闭资源
        try:
            asyncio.run(scanner.close())
        except Exception as e:
            logger.error(f"关闭扫描器时发生错误: {e}")
        
        # Windows内存清理
        if is_windows:
            try:
                import gc
                gc.collect()  # 强制垃圾回收
                logger.debug("执行垃圾回收")
            except:
                pass

if __name__ == '__main__':
    main()