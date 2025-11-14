# -*- coding: utf-8 -*-
"""
管理器模块
"""

import aiohttp
from typing import List, Optional, Dict
import random
import time
from urllib.parse import urlparse

class AuthHandler:
    """认证处理器"""
    
    def __init__(self):
        self.auth_headers = {}
        self.session = None
    
    def set_basic_auth(self, username: str, password: str):
        """设置基础认证"""
        auth_string = f"{username}:{password}"
        auth_string_bytes = auth_string.encode('utf-8')
        auth_base64 = auth_string_bytes.hex()  # 简化处理，实际使用时应该用base64
        self.auth_headers['Authorization'] = f'Basic {auth_base64}'
    
    def set_bearer_token(self, token: str):
        """设置Bearer令牌"""
        self.auth_headers['Authorization'] = f'Bearer {token}'
    
    def set_custom_header(self, key: str, value: str):
        """设置自定义头信息"""
        self.auth_headers[key] = value
    
    def get_auth_headers(self) -> Dict[str, str]:
        """获取认证头信息"""
        return self.auth_headers.copy()

class ProxyManager:
    """代理管理器"""
    
    def __init__(self, proxy_list: Optional[List[str]] = None):
        self.proxies = proxy_list or []
        self.current_proxy_index = 0
        self.proxy_usage = {}
        self.failed_proxies = set()
    
    def add_proxy(self, proxy: str):
        """添加单个代理"""
        if proxy not in self.proxies and proxy not in self.failed_proxies:
            self.proxies.append(proxy)
    
    def add_proxies(self, proxies: List[str]):
        """添加多个代理"""
        for proxy in proxies:
            self.add_proxy(proxy)
    
    def get_next_proxy(self) -> Optional[str]:
        """获取下一个可用代理"""
        if not self.proxies:
            return None
        
        # 过滤掉失败的代理
        active_proxies = [p for p in self.proxies if p not in self.failed_proxies]
        if not active_proxies:
            return None
        
        # 使用轮询方式选择代理
        proxy = active_proxies[self.current_proxy_index % len(active_proxies)]
        self.current_proxy_index += 1
        
        # 记录代理使用情况
        if proxy not in self.proxy_usage:
            self.proxy_usage[proxy] = 0
        self.proxy_usage[proxy] += 1
        
        return proxy
    
    def mark_proxy_failed(self, proxy: str):
        """标记代理失败"""
        if proxy in self.proxies:
            self.failed_proxies.add(proxy)
    
    def mark_proxy_successful(self, proxy: str):
        """标记代理成功"""
        if proxy in self.failed_proxies:
            self.failed_proxies.remove(proxy)
    
    def get_proxy_stats(self) -> Dict:
        """获取代理统计信息"""
        return {
            'total': len(self.proxies),
            'active': len([p for p in self.proxies if p not in self.failed_proxies]),
            'failed': len(self.failed_proxies),
            'usage': self.proxy_usage
        }
    
    def format_proxy_for_aiohttp(self, proxy: str) -> Dict[str, str]:
        """格式化代理以供aiohttp使用"""
        parsed = urlparse(proxy)
        scheme = parsed.scheme or 'http'
        netloc = parsed.netloc
        
        if not netloc:
            netloc = proxy
        
        return {
            'http': f'{scheme}://{netloc}',
            'https': f'{scheme}://{netloc}'
        }

class AdaptiveRateLimiter:
    """自适应速率限制器（Windows优化版）"""
    
    def __init__(self, initial_rate: int = 10, min_rate: int = 1, max_rate: int = 50):
        self.current_rate = initial_rate  # 请求/秒
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.request_timestamps = []
        self.last_rate_adjustment = time.time()
        self.fail_count = 0
        self.success_count = 0
        self.rate_adjustment_interval = 3  # 秒（Windows下更频繁调整）
        self.windows_optimization = True  # Windows系统优化模式
        self.human_like_delays = [0.1, 0.2, 0.3, 0.5, 0.8, 1.2, 1.5, 2.0]  # 人类行为延迟模式
        self.last_human_delay = 0.5
    
    def should_delay(self) -> bool:
        """检查是否应该延迟请求"""
        current_time = time.time()
        
        # 清理过期的时间戳
        self.request_timestamps = [t for t in self.request_timestamps 
                                  if current_time - t < 1.0]
        
        # 调整速率
        self._adjust_rate()
        
        # 检查是否达到速率限制
        if len(self.request_timestamps) >= self.current_rate:
            return True
        
        return False
    
    def record_request(self, success: bool):
        """记录请求结果"""
        current_time = time.time()
        self.request_timestamps.append(current_time)
        
        if success:
            self.success_count += 1
            self.fail_count = 0  # 重置失败计数
        else:
            self.fail_count += 1
            self.success_count = 0  # 重置成功计数
    
    def _adjust_rate(self):
        """自适应调整请求速率（Windows优化）"""
        current_time = time.time()
        
        # 检查是否应该调整速率
        if current_time - self.last_rate_adjustment < self.rate_adjustment_interval:
            return
        
        # Windows系统下的保守策略
        if self.windows_optimization:
            if self.fail_count >= 2 and self.current_rate > self.min_rate:  # 更早降速
                # 失败较多，大幅降低速率
                self.current_rate = max(self.min_rate, int(self.current_rate * 0.6))
                self.last_rate_adjustment = current_time
                self.fail_count = 0  # 重置计数器
            elif self.success_count >= 10 and self.current_rate < self.max_rate:  # 更谨慎提速
                # 成功较多，小幅提高速率
                self.current_rate = min(self.max_rate, int(self.current_rate * 1.05))
                self.last_rate_adjustment = current_time
                self.success_count = 0  # 重置计数器
        else:
            # 标准策略
            if self.fail_count >= 3 and self.current_rate > self.min_rate:
                self.current_rate = max(self.min_rate, int(self.current_rate * 0.8))
                self.last_rate_adjustment = current_time
            elif self.success_count >= 20 and self.current_rate < self.max_rate:
                self.current_rate = min(self.max_rate, int(self.current_rate * 1.1))
                self.last_rate_adjustment = current_time
    
    def get_delay_time(self) -> float:
        """获取延迟时间（包含人类行为模拟）"""
        current_time = time.time()
        
        # 计算应该延迟的时间
        if len(self.request_timestamps) >= self.current_rate:
            # 找到最旧的应该被替换的请求
            oldest_timestamp = sorted(self.request_timestamps)[0]
            delay = 1.0 - (current_time - oldest_timestamp)
            return max(0.0, delay)
        
        # 添加随机人类行为延迟
        import random
        human_delay = random.choice(self.human_like_delays)
        self.last_human_delay = human_delay * random.uniform(0.5, 1.5)  # 添加随机变异
        
        return self.last_human_delay
    
    def get_current_rate(self) -> int:
        """获取当前速率"""
        return self.current_rate