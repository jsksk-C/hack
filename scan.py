#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
高级目录扫描工具 - 入口脚本

此脚本提供了一个简单的方式来运行dirscanner包中的扫描功能。
"""

import sys
import os

# 添加当前目录到Python路径，确保可以导入dirscanner包
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == '__main__':
    try:
        # 从dirscanner包导入主运行函数
        from dirscanner.main import run
        # 运行扫描工具
        run()
    except ImportError as e:
        print(f"错误: 无法导入dirscanner包 - {str(e)}")
        print("请确保dirscanner包已正确安装或位于当前目录下")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"错误: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)