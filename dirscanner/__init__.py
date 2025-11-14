# -*- coding: utf-8 -*-
"""
dirscanner包 - 高级目录扫描工具

此包提供了一个模块化的高级目录扫描工具，用于发现网站上的隐藏目录和文件。

主要功能：
- 自适应速率限制
- 智能响应过滤
- 多种报告格式支持
- 代理支持
- 认证支持
- 动态字典生成

使用方法：
```python
from dirscanner import AdvancedDirectoryScanner

scanner = AdvancedDirectoryScanner('https://example.com')
results = await scanner.run_scan()
```
"""

# 导入主要模块
from .scanner import AdvancedDirectoryScanner, load_wordlist, load_proxy_list
from .models import ScanResult
from .analyzers import SmartResponseAnalyzer, ResultAnalyzer
from .generators import DynamicWordlistGenerator, ReportGenerator
from .managers import AuthHandler, ProxyManager, AdaptiveRateLimiter
from .main import run

# 版本信息
__version__ = '1.0.0'

# 导出列表
__all__ = [
    # 主要类
    'AdvancedDirectoryScanner',
    # 数据模型
    'ScanResult',
    # 分析器
    'SmartResponseAnalyzer',
    'ResultAnalyzer',
    # 生成器
    'DynamicWordlistGenerator',
    'ReportGenerator',
    # 管理器
    'AuthHandler',
    'ProxyManager',
    'AdaptiveRateLimiter',
    # 工具函数
    'load_wordlist',
    'load_proxy_list',
    # 主入口
    'run'
]