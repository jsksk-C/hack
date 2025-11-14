#!/usr/bin/env python3
"""
高级目录扫描工具 - 集成智能响应分析、动态字典生成、多认证支持等功能
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
import signal
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import deque, defaultdict
import logging
import csv
from pathlib import Path

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dirscan.log'),
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
        
        for path in test_paths:
            # 注意：这里不能直接访问stop_event，因为它属于扫描器对象
            # SmartResponseAnalyzer类没有stop_event属性
            
            try:
                # 添加超时处理
                async with asyncio.timeout(5):  # 5秒超时
                    async with session.get(urljoin(base_url, path)) as response:
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
            except asyncio.TimeoutError:
                logger.debug(f"基线测试超时: {path}")
            except Exception as e:
                logger.debug(f"基线测试失败: {path} - {e}")
        
        return self.baseline_404 is not None
    
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
        # 如果状态码明确是404
        if result.status == 404:
            return False
        
        # 创建当前响应指纹
        current_fp = self._create_fingerprint(content, result.headers or {})
        
        # 与已知404指纹比较
        for fp in self.fingerprints:
            if current_fp == fp:
                return False
        
        # 长度相似性检查
        if self.baseline_404 and result.content_length > 0:
            baseline_len = self.baseline_404.get('length', 0)
            if baseline_len > 0:
                similarity = min(baseline_len, result.content_length) / max(baseline_len, result.content_length)
                if similarity > self.similarity_threshold:
                    return False
        
        # 状态码过滤
        if result.status >= 400 and result.status not in [401, 403]:
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
    """自适应速率限制器"""
    
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
    
    async def acquire(self):
        """获取请求许可"""
        with self.lock:
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            required_interval = 1.0 / self.rps if self.rps > 0 else 0.0
            
            if elapsed < required_interval:
                sleep_time = required_interval - elapsed
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
                
                # 动态调整速率
                if success_rate > 0.95:  # 成功率很高，激进增加
                    self.rps = min(self.rps * 1.3, self.max_rps)
                elif success_rate > 0.85:  # 成功率较高，适度增加
                    self.rps = min(self.rps * 1.1, self.max_rps)
                elif success_rate < 0.5:  # 成功率低，大幅降低
                    self.rps = max(self.rps * 0.7, self.min_rps)
                elif success_rate < 0.7:  # 成功率较低，适度降低
                    self.rps = max(self.rps * 0.9, self.min_rps)
                
                # 重置计数器
                self.success_count = 0
                self.error_count = 0
                
                logger.debug(f"调整请求速率: {self.rps:.1f} RPS")

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
    """高级目录扫描器"""
    
    def __init__(self, 
                 base_url: str,
                 wordlist: List[str] = None,
                 max_concurrency: int = 50,
                 timeout: int = 10,
                 user_agent: str = None):
        
        self.base_url = base_url.rstrip('/') + '/'
        self.wordlist = wordlist or []
        self.total_paths = len(self.wordlist)
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (compatible; AdvancedDirScanner/1.0)"
        
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
        self.stop_event = threading.Event()
        
        # 统计信息
        self.stats = {
            'requests_sent': 0,
            'requests_failed': 0,
            'meaningful_responses': 0,
            'start_time': time.time()
        }
        
        # 设置信号处理
        signal.signal(signal.SIGINT, self._handle_interrupt)
        signal.signal(signal.SIGTERM, self._handle_interrupt)
    
    def _handle_interrupt(self, signum, frame):
        """处理中断信号"""
        logger.info("接收到中断信号，正在停止扫描...")
        self.stop_event.set()
        # 在Windows上，尝试抛出KeyboardInterrupt异常来中断asyncio.run
        if sys.platform == 'win32':
            logger.warning("在Windows平台上，扫描将在当前任务完成后停止")
            # 对于Windows，我们需要通过其他机制来中断asyncio循环
    
    async def initialize(self):
        """初始化扫描器"""
        # 创建会话
        connector = aiohttp.TCPConnector(limit=self.max_concurrency, verify_ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.user_agent}
        )
        
        # 建立404基线
        logger.info("正在建立404响应基线...")
        if not await self.response_analyzer.establish_baseline(self.base_url, self.session):
            logger.warning("无法建立可靠的404基线，扫描准确性可能受影响")
    
    async def scan_url(self, path: str) -> Optional[ScanResult]:
        """扫描单个URL"""
        if self.stop_event.is_set():
            return None
            
        url = urljoin(self.base_url, path)
        
        # 避免重复扫描
        with self.lock:
            if url in self.scanned_urls:
                return None
            self.scanned_urls.add(url)
        
        # 速率限制
        await self.rate_limiter.acquire()
        
        try:
            start_time = time.time()
            
            # 准备请求参数
            kwargs = {
                'allow_redirects': False,
                'headers': self.auth_handler.get_headers()
            }
            
            # 添加Cookies
            cookies = self.auth_handler.get_cookies()
            if cookies:
                kwargs['cookies'] = cookies
            
            # 添加代理
            proxy = self.proxy_manager.get_next_proxy()
            if proxy:
                kwargs['proxy'] = proxy
            
            # 发送请求，添加超时处理
            async with asyncio.timeout(self.timeout):
                async with self.session.get(url, **kwargs) as response:
                    # 再次检查是否应该停止
                    if self.stop_event.is_set():
                        return None
                    
                    response_time = time.time() - start_time
                    
                    # 限制内容读取大小，避免大文件导致的内存问题
                    max_content_size = 1024 * 1024  # 1MB
                    content = await response.text(max_chars=max_content_size)
                    
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
                    
                    # 分析响应是否有意义
                    if self.response_analyzer.is_meaningful_response(result, content):
                        self.rate_limiter.record_success()
                        self.stats['meaningful_responses'] += 1
                        return result
                    else:
                        self.rate_limiter.record_success()
                        return None
                    
        except asyncio.TimeoutError:
            self.rate_limiter.record_error()
            self.stats['requests_failed'] += 1
            logger.debug(f"请求超时: {url}")
            return None
        except Exception as e:
            self.rate_limiter.record_error()
            self.stats['requests_failed'] += 1
            logger.debug(f"请求失败: {url} - {e}")
            return None
        finally:
            self.stats['requests_sent'] += 1
    
    def _display_progress(self):
        """显示当前扫描进度"""
        if self.total_paths > 0:
            progress = (self.stats['requests_sent'] / self.total_paths) * 100
            elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
            rate = self.stats['requests_sent'] / elapsed if elapsed > 0 else 0
            
            # 使用回车符覆盖当前行，不打印新行
            print(f"\r进度: {self.stats['requests_sent']}/{self.total_paths} ({progress:.1f}%) | 速度: {rate:.2f}/秒 | 发现: {len(self.found_results)} 个路径", end='')
    
    async def run_scan(self) -> List[ScanResult]:
        """运行扫描"""
        if not self.session:
            await self.initialize()
        
        logger.info(f"开始扫描 {self.base_url}")
        logger.info(f"字典大小: {self.total_paths}")
        logger.info(f"并发数: {self.max_concurrency}")
        logger.info("按 Ctrl+C 中断扫描")
        
        # 创建信号量控制并发
        semaphore = asyncio.Semaphore(self.max_concurrency)
        
        async def controlled_scan(path):
            async with semaphore:
                return await self.scan_url(path)
        
        # 创建并跟踪任务，而不是一次性使用gather
        tasks = []
        for path in self.wordlist:
            # 检查是否应该停止
            if self.stop_event.is_set():
                logger.info(f"扫描已中断，已处理 {len(tasks)} 个路径")
                break
            
            task = asyncio.create_task(controlled_scan(path))
            tasks.append(task)
        
        # 使用wait而不是gather，这样可以在收到停止信号时取消剩余任务
        done = []
        pending = set(tasks)
        
        while pending:
            # 等待任意任务完成或收到停止信号
            done, pending = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # 检查是否收到停止信号
            if self.stop_event.is_set():
                logger.info(f"取消剩余的 {len(pending)} 个任务")
                for task in pending:
                    task.cancel()
                break
            
            # 处理已完成的任务
            for task in done:
                try:
                    result = await task
                    if isinstance(result, ScanResult) and result:
                        self.found_results.append(result)
                        self._print_result(result)
                    self._display_progress()
                except asyncio.CancelledError:
                    logger.debug("任务被取消")
                except Exception as e:
                    logger.debug(f"任务异常: {e}")
        
        print("\n扫描完成!")
        logger.info(f"扫描完成，找到 {len(self.found_results)} 个有意义的结果")
        return self.found_results
    
    def _print_result(self, result: ScanResult):
        """打印扫描结果"""
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
            return self.report_generator.generate_json_report(self.found_results, self.stats, output_file)
        elif format.lower() == 'csv':
            return self.report_generator.generate_csv_report(self.found_results, output_file)
        elif format.lower() == 'html':
            return self.report_generator.generate_html_report(self.found_results, self.stats, output_file)
        else:
            logger.error(f"不支持的报告格式: {format}")
            return None
    
    def print_summary(self):
        """打印扫描摘要"""
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
        """关闭扫描器"""
        if self.session:
            await self.session.close()

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
    parser = argparse.ArgumentParser(description='高级目录扫描工具')
    parser.add_argument('url', help='目标URL')
    parser.add_argument('-w', '--wordlist', help='字典文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'html'], 
                       default='json', help='输出格式')
    parser.add_argument('-t', '--threads', type=int, default=50, help='并发线程数')
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
    parser.add_argument('--rps', type=float, default=10.0, help='初始每秒请求数')
    parser.add_argument('--max-rps', type=float, default=50.0, help='最大每秒请求数')
    parser.add_argument('--min-rps', type=float, default=1.0, help='最小每秒请求数')
    
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
    
    # 创建扫描器
    scanner = AdvancedDirectoryScanner(
        base_url=args.url,
        wordlist=wordlist,
        max_concurrency=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    # 配置速率限制
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
    loop = None
    try:
        # 创建事件循环
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # 在Windows上，使用更可靠的方式处理KeyboardInterrupt
        if sys.platform == 'win32':
            # Windows上设置特殊的中断处理
            def win_interrupt_handler(signum, frame):
                logger.info("Windows平台: 接收到中断信号")
                scanner.stop_event.set()
                # 如果有正在运行的任务，尝试取消它们
                for task in asyncio.all_tasks(loop):
                    task.cancel()
            
            # 在Windows上重新设置信号处理
            signal.signal(signal.SIGINT, win_interrupt_handler)
        
        # 运行扫描
        results = loop.run_until_complete(scanner.run_scan())
        scanner.print_summary()
        
        # 生成报告
        if args.output:
            scanner.generate_report(args.output, args.format)
            logger.info(f"报告已保存到: {args.output}")
    except KeyboardInterrupt:
            logger.info("扫描被用户中断")
            print("\n扫描被用户中断")
            # 确保停止事件被设置
            scanner.stop_event.set()
            # 取消所有任务
            if loop:
                for task in asyncio.all_tasks(loop):
                    task.cancel()
                # 给一个小的延迟让任务有机会取消
                try:
                    loop.run_until_complete(asyncio.sleep(0.1))
                except:
                    pass
    except Exception as e:
            logger.error(f"扫描过程中发生错误: {e}")
            print(f"\n扫描过程中发生错误: {e}")
            import traceback
            logger.debug(traceback.format_exc())
    finally:
        # 确保关闭扫描器和事件循环
        try:
            if loop:
                # 关闭扫描器
                loop.run_until_complete(scanner.close())
                # 关闭事件循环
                loop.close()
        except Exception as e:
            logger.error(f"清理资源时出错: {e}")

if __name__ == '__main__':
    main()