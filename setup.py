#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
dirscanner包的安装脚本
"""

from setuptools import setup, find_packages
import sys
import os

# 获取包的版本号
try:
    with open(os.path.join('dirscanner', '__init__.py'), 'r') as f:
        for line in f:
            if line.startswith('__version__'):
                version = line.strip().split('=')[1].strip().strip('"').strip("'")
                break
        else:
            version = '0.1.0'
except Exception:
    version = '0.1.0'

# 读取README文件内容
try:
    with open('README.md', 'r', encoding='utf-8') as f:
        long_description = f.read()
except Exception:
    long_description = "高级目录扫描工具"

# 定义依赖项
install_requires = [
    'aiohttp>=3.8.0',
    'asyncio>=3.4.3',
]

# 设置包的配置
setup(
    name='dirscanner',
    version=version,
    description='高级目录扫描工具',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='PyHack-Lab',
    author_email='',
    url='',
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'dirscanner=dirscanner.main:run',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Utilities',
    ],
    keywords='directory-scanner, security, penetration-testing, web-security',
)