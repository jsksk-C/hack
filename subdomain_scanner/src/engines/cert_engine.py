"""证书透明日志（CT）查询引擎——占位实现"""
from .base_engine import BaseEngine

class CertEngine(BaseEngine):
    def search(self, target: str):
        # 占位：实际实现会调用 CT 日志服务或 crt.sh
        # 返回示例空列表以示意接口
        return []
