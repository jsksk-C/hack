# -*- coding: utf-8 -*-
"""
分析器模块
"""

import asyncio
import hashlib
import re
from typing import Dict, List, Set, Optional
from collections import defaultdict
import aiohttp

from .models import ScanResult

class SmartResponseAnalyzer:
    """智能响应分析器"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.baseline_404 = None
        self.fingerprints = set()
        self.similarity_threshold = 0.95
        self.common_404_patterns = [
            r'not found', r'404', r'error', r'找不到', r'页面不存在',
            r'object not found', r'file not found', r'page not found',
            r'resource not found', r'无法找到', r'未找到', r'不存在'
        ]
        
    async def establish_baseline(self, session: aiohttp.ClientSession, headers: Dict) -> bool:
        """建立404页面基线"""
        import time
        import random
        from urllib.parse import urljoin
        import logging
        base_url = self.target_url
        
        logger = logging.getLogger(__name__)
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
                
                async with session.get(test_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
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
    
    def _create_fingerprint(self, content, headers: Dict) -> str:
        """创建响应指纹"""
        # 将内容转换为字符串（如果是bytes）
        if isinstance(content, bytes):
            try:
                content_str = content.decode('utf-8', errors='ignore')
            except:
                content_str = str(content)
        else:
            content_str = content
        
        features = []
        features.append(f"len:{len(content_str)}")
        
        title_match = re.search(r'<title>(.*?)</title>', content_str, re.IGNORECASE)
        if title_match:
            features.append(f"title:{title_match.group(1).lower()[:50]}")
        
        for keyword in self.common_404_patterns:
            if keyword.lower() in content_str.lower():
                features.append(f"kw:{keyword}")
        
        if 'Server' in headers:
            features.append(f"server:{headers['Server']}")
        
        return hashlib.md5('|'.join(features).encode()).hexdigest()
    
    def is_meaningful_response(self, result: ScanResult, content) -> bool:
        """判断响应是否有意义"""
        if result.status == 404:
            return False
            
        if 500 <= result.status < 600:
            return False
        
        # 将内容转换为字符串（如果是bytes）
        if isinstance(content, bytes):
            try:
                content_str = content.decode('utf-8', errors='ignore')
            except:
                content_str = str(content)
        else:
            content_str = content
        
        current_fp = self._create_fingerprint(content_str, result.headers or {})
        
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