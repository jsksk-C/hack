#!/usr/bin/env python3
"""
高级目录扫描工具 - Windows 11完全优化版本
修复卡住和停止输出问题
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
import gc

# 忽略特定警告
warnings.filterwarnings('ignore', category=DeprecationWarning, module='aiohttp')

# Windows特定导入和优化
if sys.platform == 'win32':
    try:
        import win32api
        HAS_WIN32 = True
        # Windows事件循环策略
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except ImportError:
        HAS_WIN32 = False
else:
    HAS_WIN32 = False

# 配置日志
def setup_logging(verbose=False):
    """设置日志记录"""
    level = logging.DEBUG if verbose else logging.INFO
    
    # 创建日志目录
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 设置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # 清除现有的处理器
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # 文件处理器
    file_handler = logging.FileHandler(
        os.path.join(log_dir, "dirscan_debug.log"),
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    
    # 设置格式
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return root_logger

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
        self.similarity_threshold = 0.95
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
            "/this-path-should-not-exist-12345"
        ]
        
        logger.info("正在测试404基线...")
        baseline_results = []
        
        for i, path in enumerate(test_paths):
            try:
                test_url = urljoin(base_url, path)
                logger.debug(f"基线测试 {i+1}/{len(test_paths)}: {test_url}")
                
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    content = await response.text()
                    fingerprint = self._create_fingerprint(content, response.headers)
                    baseline_results.append({
                        'status': response.status,
                        'length': len(content),
                        'fingerprint': fingerprint,
                        'headers': dict(response.headers)
                    })
                    self.fingerprints.add(fingerprint)
                    
            except asyncio.TimeoutError:
                logger.debug(f"基线测试超时: {test_url}")
            except Exception as e:
                logger.debug(f"基线测试失败: {test_url} - {e}")
        
        # 选择最常见的响应作为基线
        if baseline_results:
            status_groups = defaultdict(list)
            for result in baseline_results:
                status_groups[result['status']].append(result)
            
            if status_groups:
                most_common_status = max(status_groups.keys(), 
                                       key=lambda x: len(status_groups[x]))
                self.baseline_404 = status_groups[most_common_status][0]
                logger.info(f"基线建立成功: 状态码={self.baseline_404['status']}, 长度={self.baseline_404['length']}")
                return True
        
        logger.warning("无法建立可靠的404基线")
        return False
    
    def _create_fingerprint(self, content: str, headers: Dict) -> str:
        """创建响应指纹"""
        features = []
        features.append(f"len:{len(content)}")
        
        title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
        if title_match:
            features.append(f"title:{title_match.group(1).lower()[:50]}")
        
        for keyword in self.common_404_patterns:
            if keyword.lower() in content.lower():
                features.append(f"kw:{keyword}")
        
        if 'Server' in headers:
            features.append(f"server:{headers['Server']}")
        
        return hashlib.md5('|'.join(features).encode()).hexdigest()
    
    def is_meaningful_response(self, result: ScanResult, content: str) -> bool:
        """判断响应是否有意义"""
        if result.status == 404:
            return False
            
        if 500 <= result.status < 600:
            return False
        
        current_fp = self._create_fingerprint(content, result.headers or {})
        
        for fp in self.fingerprints:
            if current_fp == fp:
                return False
        
        if self.baseline_404 and result.content_length > 0:
            baseline_len = self.baseline_404.get('length', 0)
            if baseline_len > 0:
                similarity = min(baseline_len, result.content_length) / max(baseline_len, result.content_length)
                if similarity > self.similarity_threshold:
                    return False
        
        if 300 <= result.status < 400 and result.redirect_url:
            if any(pattern in result.redirect_url.lower() for pattern in ['error', '404', 'notfound']):
                return False
                
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
        domain = domain.split(':')[0]
        
        parts = domain.split('.')
        if len(parts) >= 2:
            if parts[0] in ['www', 'api', 'app', 'test', 'dev', 'staging']:
                return parts[1] if len(parts) > 1 else parts[0]
            return parts[0]
        return domain
    
    def _load_common_directories(self) -> List[str]:
        """加载常见目录列表"""
        return [
            'admin', 'administrator', 'admincp', 'adminpanel', 'manager', 
            'management', 'dashboard', 'control', 'console', 'backend',
            'webadmin', 'cpanel', 'panel', 'login', 'logon', 'signin',
            'config', 'configuration', 'settings', 'setup', 'install',
            'installer', 'update', 'upgrade', 'etc', 'conf',
            'backup', 'backups', 'bak', 'old', 'archive', 'archives',
            'back', 'backup_old', 'database_backup', 'db_backup',
            'src', 'source', 'code', 'develop', 'development', 'dev',
            'build', 'dist', 'app', 'application', 'apps', 'web',
            'www', 'public', 'public_html', 'html', 'htdocs',
            'api', 'apis', 'rest', 'json', 'xml', 'soap', 'webservice',
            'assets', 'static', 'media', 'upload', 'uploads', 'files',
            'images', 'img', 'css', 'js', 'javascript', 'fonts',
            'bin', 'boot', 'lib', 'opt', 'proc', 'root', 'sbin', 'usr', 'var',
            'test', 'tests', 'testing', 'docs', 'document', 'doc', 'wiki',
            '.git', '.svn', '.hg', '.cvs',
            'wp-admin', 'wp-content', 'wp-includes', 'administrator',
            'sites', 'modules', 'themes', 'plugins', 'components'
        ]
    
    def _load_common_files(self) -> List[str]:
        """加载常见文件列表"""
        return [
            'config.php', 'config.json', 'config.xml', 'config.yml',
            'config.ini', 'settings.php', 'database.php', 'db.php',
            '.env', '.env.local', '.env.production',
            'backup.sql', 'backup.zip', 'backup.tar', 'backup.tar.gz',
            'dump.sql', 'database_dump.sql',
            'admin.php', 'administrator.php', 'login.php', 'panel.php',
            'index.php', 'index.html', 'default.html', 'home.html',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'security.txt', 'humans.txt', 'favicon.ico',
            'error.log', 'access.log', 'debug.log',
            '.gitignore', '.git/config', '.svn/entries',
            '.htaccess', 'web.config', 'httpd.conf'
        ]
    
    def generate_target_specific_words(self) -> List[str]:
        """生成目标特定的字典"""
        words = set()
        target_name = self.target_name.lower()
        
        if not target_name or target_name in ['localhost', '127.0.0.1']:
            return list(set(self.common_dirs + self.common_files))
        
        target_variants = [
            target_name,
            f"{target_name}-admin", f"{target_name}-panel", f"{target_name}-login",
            f"{target_name}-backup", f"{target_name}-test", f"{target_name}-dev",
            f"admin-{target_name}", f"backup-{target_name}", f"test-{target_name}",
            f"dev-{target_name}", f"staging-{target_name}", f"prod-{target_name}",
            f"{target_name}2023", f"{target_name}2024", f"{target_name}_backup",
            f"{target_name}_old", f"{target_name}_new", f"{target_name}_test"
        ]
        
        words.update(self.common_dirs)
        words.update(self.common_files)
        words.update(target_variants)
        
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
    """自适应速率限制器 - Windows优化版本"""
    
    def __init__(self, initial_rps: float = 5.0, max_rps: float = 20.0, min_rps: float = 1.0):
        self.rps = initial_rps
        self.max_rps = max_rps
        self.min_rps = min_rps
        self.last_request_time = 0
        self.error_count = 0
        self.success_count = 0
        self.adjustment_interval = 20
        self.request_count = 0
        self.lock = asyncio.Lock()
        self.request_times = deque(maxlen=50)
        self._semaphore_limit = int(max_rps * 1.5)
        self._semaphore = asyncio.Semaphore(self._semaphore_limit)
    
    async def acquire(self):
        """获取请求许可"""
        async with self._semaphore:
            async with self.lock:
                current_time = time.time()
                self.request_times.append(current_time)
                
                if len(self.request_times) >= 2:
                    time_span = self.request_times[-1] - self.request_times[0]
                    if time_span > 0:
                        current_rps = len(self.request_times) / time_span
                        if current_rps > self.rps:
                            sleep_time = 1.0 / self.rps
                            await asyncio.sleep(sleep_time)
                
                self.last_request_time = time.time()
    
    def record_success(self):
        """记录成功请求"""
        self.success_count += 1
        self._adjust_rate()
    
    def record_error(self):
        """记录错误请求"""
        self.error_count += 1
        self._adjust_rate()
    
    def _adjust_rate(self):
        """调整请求速率"""
        self.request_count += 1
        
        if self.request_count % self.adjustment_interval == 0:
            total_requests = self.success_count + self.error_count
            if total_requests > 0:
                success_rate = self.success_count / total_requests
                
                if success_rate > 0.95:
                    self.rps = min(self.rps * 1.05, self.max_rps)
                elif success_rate > 0.85:
                    self.rps = min(self.rps * 1.02, self.max_rps)
                elif success_rate < 0.5:
                    self.rps = max(self.rps * 0.7, self.min_rps)
                elif success_rate < 0.7:
                    self.rps = max(self.rps * 0.9, self.min_rps)
                
                self.success_count = 0
                self.error_count = 0

class ResultAnalyzer:
    """结果分析器"""
    
    def __init__(self):
        self.risk_patterns = {
            'critical': [
                r'\.env', r'config\.', r'\.htaccess', r'web\.config',
                r'passwd', r'shadow', r'private', r'secret',
                r'dump\.sql', r'backup\.sql', r'database',
                r'phpmyadmin', r'adminer', r'webmin',
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
        
        if status == 403:
            return 'high'
        elif status == 401:
            return 'medium'
        
        for level, patterns in self.risk_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    return level
        
        if status == 200:
            if content_length == 0:
                return 'low'
            elif content_length > 1000000:
                return 'medium'
        
        return 'info'
    
    def cluster_results(self, results: List[ScanResult]) -> Dict[str, List[ScanResult]]:
        """聚类扫描结果"""
        clusters = {
            'critical': [], 'high': [], 'medium': [], 
            'low': [], 'info': [], 'redirects': []
        }
        
        for result in results:
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
        
        for risk_level, risk_results in clusters.items():
            report['results_by_risk'][risk_level] = [r.to_dict() for r in risk_results]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report
    
    def generate_csv_report(self, results: List[ScanResult], output_file: str):
        """生成CSV格式报告"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Status', 'Content Length', 'Content Type', 
                           'Title', 'Redirect URL', 'Response Time', 'Risk Level'])
            
            for result in results:
                writer.writerow([
                    result.url, result.status, result.content_length, 
                    result.content_type, result.title, result.redirect_url,
                    result.response_time, result.risk_level
                ])
    
    def generate_html_report(self, results: List[ScanResult], stats: Dict, output_file: str):
        """生成HTML格式报告"""
        analyzer = ResultAnalyzer()
        clusters = analyzer.cluster_results(results)
        
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
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

class AdvancedDirectoryScanner:
    """高级目录扫描器 - Windows 11完全优化版本"""
    
    def __init__(self, 
                 base_url: str,
                 wordlist: List[str] = None,
                 max_concurrency: int = 15,
                 timeout: int = 10,
                 user_agent: str = None,
                 output_timeout: int = 30):
        
        self.base_url = base_url.rstrip('/') + '/'
        self.wordlist = wordlist or []
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.output_timeout = output_timeout
        
        self.scanned_urls = set()
        self.found_results = []
        self.session = None
        self.lock = asyncio.Lock()
        self.stop_event = asyncio.Event()
        self.last_output_time = time.time()
        self.last_heartbeat_time = time.time()
        
        self.stats = {
            'requests_sent': 0,
            'requests_failed': 0,
            'meaningful_responses': 0,
            'start_time': time.time()
        }
        
        self.response_analyzer = SmartResponseAnalyzer()
        self.auth_handler = AuthHandler()
        self.proxy_manager = ProxyManager()
        self.rate_limiter = AdaptiveRateLimiter()
        self.result_analyzer = ResultAnalyzer()
        self.report_generator = ReportGenerator()
        
        self.active_tasks = set()
        self.heartbeat_task = None
        self.monitor_task = None
    
    async def initialize(self):
        """初始化扫描器"""
        try:
            logger.info(f"初始化扫描器，目标: {self.base_url}")
            
            connector = aiohttp.TCPConnector(
                limit=self.max_concurrency,
                limit_per_host=self.max_concurrency,
                use_dns_cache=True,
                ttl_dns_cache=300,
                force_close=False,
                enable_cleanup_closed=True,
                ssl=False
            )
            
            timeout = aiohttp.ClientTimeout(
                total=self.timeout,
                connect=5,
                sock_connect=10,
                sock_read=15
            )
            
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': self.user_agent},
                raise_for_status=False
            )
            
            logger.info("测试目标服务器连接...")
            try:
                async with self.session.get(self.base_url, allow_redirects=False) as test_resp:
                    logger.info(f"目标服务器响应: {test_resp.status}")
            except Exception as e:
                logger.error(f"连接测试失败: {e}")
                raise
            
            logger.info("建立404响应基线...")
            await self.response_analyzer.establish_baseline(self.base_url, self.session)
            
            self.monitor_task = asyncio.create_task(self._output_monitor())
            self.heartbeat_task = asyncio.create_task(self._heartbeat())
            
            logger.info("扫描器初始化完成")
                
        except Exception as e:
            logger.error(f"初始化失败: {e}")
            if self.session:
                await self.session.close()
            raise
    
    async def _output_monitor(self):
        """输出监控"""
        try:
            while not self.stop_event.is_set():
                await asyncio.sleep(5)
                
                current_time = time.time()
                time_since_output = current_time - self.last_output_time
                
                if time_since_output > self.output_timeout:
                    active_count = len([t for t in self.active_tasks if not t.done()])
                    
                    if active_count > 0:
                        logger.warning(f"超过{self.output_timeout}秒无输出，但有{active_count}个活跃任务，继续等待...")
                        self.last_output_time = current_time
                    else:
                        logger.error(f"超过{self.output_timeout}秒无输出且无活跃任务，停止扫描")
                        await self._stop_scan()
                        break
                        
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"输出监控错误: {e}")
    
    async def _heartbeat(self):
        """心跳机制"""
        try:
            heartbeat_interval = 60
            while not self.stop_event.is_set():
                await asyncio.sleep(heartbeat_interval)
                
                if self.stop_event.is_set():
                    break
                
                current_time = time.time()
                time_since_output = current_time - self.last_output_time
                
                if time_since_output > 30:
                    scanned_count = len(self.scanned_urls)
                    meaningful_count = self.stats['meaningful_responses']
                    logger.info(f"心跳: 已扫描{scanned_count}个URL，发现{meaningful_count}个有效结果")
                    self.last_output_time = current_time
                    
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"心跳任务错误: {e}")
    
    async def scan_url(self, path: str) -> Optional[ScanResult]:
        """扫描单个URL"""
        if self.stop_event.is_set():
            return None
            
        url = urljoin(self.base_url, path)
        
        async with self.lock:
            if url in self.scanned_urls:
                return None
            self.scanned_urls.add(url)
        
        await self.rate_limiter.acquire()
        
        try:
            start_time = time.time()
            
            kwargs = {
                'allow_redirects': False,
                'headers': self.auth_handler.get_headers(),
                'timeout': aiohttp.ClientTimeout(total=15)
            }
            
            cookies = self.auth_handler.get_cookies()
            if cookies:
                kwargs['cookies'] = cookies
            
            async with self.session.get(url, **kwargs) as response:
                response_time = time.time() - start_time
                content = await response.text()
                
                result = ScanResult(
                    url=url,
                    status=response.status,
                    content_length=len(content),
                    content_type=response.headers.get('Content-Type', ''),
                    redirect_url=response.headers.get('Location', ''),
                    headers=dict(response.headers),
                    response_time=response_time
                )
                
                title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
                if title_match:
                    result.title = title_match.group(1).strip()[:100]
                
                # 智能过滤策略：平衡准确性和发现率
                # 1. 特殊状态码优先：401(未授权)和403(禁止访问)通常表示真实存在的资源
                if result.status == 401 or result.status == 403:
                    self.rate_limiter.record_success()
                    self.stats['meaningful_responses'] += 1
                    return result
                
                # 2. 对于200状态码，需要更仔细的分析
                elif result.status == 200:
                    # 创建响应指纹
                    current_fp = self.response_analyzer._create_fingerprint(content, result.headers or {})
                    
                    # 检查是否与已知的404指纹相同
                    is_likely_404 = False
                    for fp in self.response_analyzer.fingerprints:
                        if current_fp == fp:
                            is_likely_404 = True
                            break
                    
                    # 检查内容相似度
                    content_similarity = False
                    if self.response_analyzer.baseline_404 and result.content_length > 0:
                        baseline_len = self.response_analyzer.baseline_404.get('length', 0)
                        if baseline_len > 0:
                            # 使用更宽松的阈值0.95（而不是默认的0.85）
                            similarity = min(baseline_len, result.content_length) / max(baseline_len, result.content_length)
                            if similarity > 0.95:  # 更宽松的阈值
                                content_similarity = True
                    
                    # 检查内容中是否包含明显的404关键字
                    has_404_keywords = False
                    for keyword in self.response_analyzer.common_404_patterns:
                        if keyword.lower() in content.lower() and len(content) < baseline_len * 1.5:  # 内容长度接近基线
                            has_404_keywords = True
                            break
                    
                    # 如果不是明显的假200，则视为有效响应
                    if not (is_likely_404 and content_similarity and has_404_keywords):
                        self.rate_limiter.record_success()
                        self.stats['meaningful_responses'] += 1
                        return result
                    else:
                        logger.debug(f"过滤掉的假200响应: {url} - 标题: {result.title}")
                
                # 3. 对于重定向响应，只过滤明显指向错误页面的重定向
                elif 300 <= result.status < 400 and result.redirect_url:
                    if not any(pattern in result.redirect_url.lower() for pattern in ['error', '404', 'notfound', 'not-found']):
                        self.rate_limiter.record_success()
                        self.stats['meaningful_responses'] += 1
                        return result
                
                # 4. 对于其他非500错误的响应，也考虑返回
                elif result.status < 500 and result.status != 404:
                    self.rate_limiter.record_success()
                    self.stats['meaningful_responses'] += 1
                    return result
                
                # 默认情况：过滤掉
                self.rate_limiter.record_success()
                return None
                    
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.rate_limiter.record_error()
            self.stats['requests_failed'] += 1
            return None
        except Exception as e:
            logger.error(f"扫描URL异常 {url}: {e}")
            self.rate_limiter.record_error()
            self.stats['requests_failed'] += 1
            return None
        finally:
            self.stats['requests_sent'] += 1
            self.last_output_time = time.time()
    
    async def run_scan(self) -> List[ScanResult]:
        """运行扫描"""
        if not self.session:
            await self.initialize()
        
        logger.info(f"开始扫描 {self.base_url}")
        logger.info(f"字典大小: {len(self.wordlist)}")
        logger.info(f"并发数: {self.max_concurrency}")
        
        if not self.wordlist:
            logger.warning("字典为空")
            return []
        
        semaphore = asyncio.Semaphore(min(self.max_concurrency, 20))
        
        async def scan_with_semaphore(path):
            """带并发控制的扫描函数"""
            if self.stop_event.is_set():
                return None
                
            try:
                async with semaphore:
                    if self.stop_event.is_set():
                        return None
                    return await self.scan_url(path)
            except asyncio.CancelledError:
                return None
            except Exception as e:
                logger.error(f"扫描任务异常 {path}: {e}")
                return None
        
        batch_size = min(100, len(self.wordlist) // 10 + 1)
        total_processed = 0
        results = []
        
        try:
            for i in range(0, len(self.wordlist), batch_size):
                if self.stop_event.is_set():
                    break
                    
                batch = self.wordlist[i:i + batch_size]
                logger.debug(f"处理批次 {i//batch_size + 1}/{(len(self.wordlist)-1)//batch_size + 1}")
                
                batch_tasks = []
                for path in batch:
                    if self.stop_event.is_set():
                        break
                    task = asyncio.create_task(scan_with_semaphore(path))
                    batch_tasks.append(task)
                    self.active_tasks.add(task)
                    task.add_done_callback(self.active_tasks.discard)
                
                if batch_tasks:
                    batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                    
                    for result in batch_results:
                        if isinstance(result, ScanResult) and result:
                            results.append(result)
                            self.found_results.append(result)
                            self._print_result(result)
                    
                    total_processed += len(batch)
                    
                    if total_processed % 500 == 0:
                        progress = total_processed / len(self.wordlist) * 100
                        logger.info(f"进度: {total_processed}/{len(self.wordlist)} ({progress:.1f}%)")
                        gc.collect()
                
                await asyncio.sleep(0.1)
                
        except asyncio.CancelledError:
            logger.info("扫描被取消")
        except Exception as e:
            logger.error(f"扫描过程异常: {e}")
        finally:
            if self.active_tasks:
                logger.info("等待剩余任务完成...")
                try:
                    await asyncio.wait(self.active_tasks, timeout=30)
                except asyncio.TimeoutError:
                    logger.warning("等待任务完成超时")
            
            logger.info(f"扫描完成，共处理 {total_processed} 个路径")
        
        return results
    
    async def run_scan_with_timeout(self, timeout=600):
        """带超时的扫描运行"""
        try:
            return await asyncio.wait_for(self.run_scan(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.error(f"扫描超时 ({timeout}秒)")
            await self._stop_scan()
            return self.found_results
    
    def _print_result(self, result: ScanResult):
        """打印扫描结果"""
        self.last_output_time = time.time()
        
        status_colors = {
            200: '\033[92m', 301: '\033[96m', 302: '\033[96m',
            403: '\033[93m', 401: '\033[93m', 500: '\033[91m'
        }
        
        risk_colors = {
            'critical': '\033[91m', 'high': '\033[93m', 'medium': '\033[92m',
            'low': '\033[94m', 'info': '\033[0m', 'redirects': '\033[96m'
        }
        
        reset = '\033[0m'
        status_color = status_colors.get(result.status, '\033[0m')
        risk_color = risk_colors.get(result.risk_level, '\033[0m')
        
        status_str = f"{status_color}{result.status}{reset}"
        risk_str = f"{risk_color}[{result.risk_level.upper()}]{reset}"
        length_str = f"{result.content_length}" if result.content_length > 0 else "0"
        
        output = f"{risk_str} [{status_str}] {result.url}"
        if result.redirect_url:
            output += f" -> {result.redirect_url}"
        if result.title:
            output += f" [{result.title[:50]}]"
        output += f" ({length_str} bytes)"
        
        print(output)
    
    async def _stop_scan(self):
        """停止扫描"""
        self.stop_event.set()
        
        for task in self.active_tasks:
            if not task.done():
                task.cancel()
        
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
        if self.monitor_task:
            self.monitor_task.cancel()
    
    async def close(self):
        """关闭扫描器"""
        await self._stop_scan()
        
        if self.session:
            await self.session.close()
            self.session = None
        
        gc.collect()
    
    def print_summary(self):
        """打印扫描摘要"""
        total_time = time.time() - self.stats['start_time']
        req_per_sec = self.stats['requests_sent'] / total_time if total_time > 0 else 0
        
        print("\n" + "="*60)
        print("扫描摘要")
        print("="*60)
        print(f"目标URL: {self.base_url}")
        print(f"扫描时长: {total_time:.2f} 秒")
        print(f"总请求数: {self.stats['requests_sent']}")
        print(f"成功响应: {self.stats['meaningful_responses']}")
        print(f"失败请求: {self.stats['requests_failed']}")
        print(f"请求速率: {req_per_sec:.1f} 请求/秒")
        print(f"扫描完成率: {len(self.scanned_urls)}/{len(self.wordlist)}")
    
    def generate_report(self, output_file: str = None, format: str = 'json'):
        """生成扫描报告"""
        try:
            if output_file:
                output_dir = os.path.dirname(output_file)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
            
            total_time = time.time() - self.stats['start_time']
            req_per_sec = self.stats['requests_sent'] / total_time if total_time > 0 else 0
            
            self.stats.update({
                'target': self.base_url,
                'duration': total_time,
                'requests_per_second': req_per_sec
            })
            
            if format.lower() == 'json':
                self.report_generator.generate_json_report(self.found_results, self.stats, output_file)
            elif format.lower() == 'csv':
                self.report_generator.generate_csv_report(self.found_results, output_file)
            elif format.lower() == 'html':
                self.report_generator.generate_html_report(self.found_results, self.stats, output_file)
            
            if output_file:
                logger.info(f"{format.upper()}报告已保存到: {output_file}")
                
        except Exception as e:
            logger.error(f"生成报告失败: {e}")

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
    """主函数"""
    if sys.platform == 'win32':
        if sys.stdout.encoding != 'utf-8':
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except:
                pass
    
    parser = argparse.ArgumentParser(description='高级目录扫描工具 - Windows 11优化版')
    parser.add_argument('url', help='目标URL')
    parser.add_argument('-w', '--wordlist', help='字典文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'html'], default='json')
    parser.add_argument('-t', '--threads', type=int, default=15, help='并发线程数 (Windows推荐: 10-20)')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='请求超时时间')
    parser.add_argument('--user-agent', help='自定义User-Agent')
    parser.add_argument('--proxy', help='代理服务器')
    parser.add_argument('--proxy-list', help='代理列表文件')
    parser.add_argument('--auth', help='基本认证 (用户名:密码)')
    parser.add_argument('--cookie', help='Cookie字符串')
    parser.add_argument('--generate-wordlist', action='store_true', help='基于目标生成动态字典')
    parser.add_argument('--save-wordlist', help='保存生成的字典到文件')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    parser.add_argument('--rps', type=float, default=5.0, help='初始每秒请求数')
    parser.add_argument('--max-rps', type=float, default=15.0, help='最大每秒请求数')
    parser.add_argument('--scan-timeout', type=int, default=600, help='总扫描超时时间（秒）')
    parser.add_argument('--output-timeout', type=int, default=30, help='无输出超时时间（秒）')
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    wordlist = []
    
    if args.wordlist and os.path.exists(args.wordlist):
        wordlist = load_wordlist(args.wordlist)
        logger.info(f"从文件加载字典: {len(wordlist)} 条目")
    
    if args.generate_wordlist or not wordlist:
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
    
    wordlist = list(set(wordlist))
    
    if not wordlist:
        logger.error("没有可用的字典")
        return 1
    
    if sys.platform == 'win32' and len(wordlist) > 10000:
        logger.warning(f"大字典警告: {len(wordlist)} 个条目，建议分批扫描")
        if args.threads > 20:
            logger.warning("并发数过高，自动调整为20")
            args.threads = 20
    
    scanner = AdvancedDirectoryScanner(
        base_url=args.url,
        wordlist=wordlist,
        max_concurrency=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        output_timeout=args.output_timeout
    )
    
    if args.auth:
        try:
            username, password = args.auth.split(':', 1)
            scanner.auth_handler.set_basic_auth(username, password)
        except ValueError:
            logger.error("认证格式错误，应为 用户名:密码")
    
    if args.cookie:
        cookies = {}
        for item in args.cookie.split(';'):
            if '=' in item:
                key, value = item.strip().split('=', 1)
                cookies[key] = value
        scanner.auth_handler.set_cookies(cookies)
    
    if args.proxy:
        scanner.proxy_manager = ProxyManager([args.proxy])
    elif args.proxy_list:
        proxy_list = load_proxy_list(args.proxy_list)
        if proxy_list:
            scanner.proxy_manager = ProxyManager(proxy_list)
    
    try:
        results = asyncio.run(scanner.run_scan_with_timeout(args.scan_timeout))
        
        scanner.print_summary()
        
        if args.output:
            scanner.generate_report(args.output, args.format)
        
        if sys.platform == 'win32':
            print("\n=== Windows使用提示 ===")
            print("✓ 如遇性能问题，可降低并发数 (-t 10)")
            print("✓ 大字典建议分批扫描")
            print("✓ 查看 logs/dirscan_debug.log 获取详细日志")
            
        return 0
        
    except KeyboardInterrupt:
        logger.info("扫描被用户中断")
        return 130
    except Exception as e:
        logger.error(f"扫描失败: {e}")
        return 1
    finally:
        try:
            asyncio.run(scanner.close())
        except:
            pass
        
        if sys.platform == 'win32':
            gc.collect()

if __name__ == '__main__':
    sys.exit(main())