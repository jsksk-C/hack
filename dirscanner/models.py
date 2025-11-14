# -*- coding: utf-8 -*-
"""
数据模型模块
"""

from dataclasses import dataclass, asdict
from typing import Dict, Optional

@dataclass
class ScanResult:
    """扫描结果数据类"""
    url: str
    status: int
    content_length: int
    content_type: str = ""
    title: str = ""
    redirect_url: str = ""
    headers: Optional[Dict] = None
    response_time: float = 0.0
    risk_level: str = "info"
    content: Optional[str] = None
    is_meaningful: bool = False
    
    def to_dict(self) -> Dict:
        """转换为字典，处理bytes类型数据"""
        result_dict = asdict(self)
        # 处理bytes类型数据，转换为字符串
        for key, value in result_dict.items():
            if isinstance(value, bytes):
                try:
                    result_dict[key] = value.decode('utf-8')
                except UnicodeDecodeError:
                    result_dict[key] = str(value)
        return result_dict