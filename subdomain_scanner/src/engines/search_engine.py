"""搜索引擎查询（占位），例如使用搜索引擎或被动源"""
from .base_engine import BaseEngine

class SearchEngine(BaseEngine):
    def search(self, target: str):
        # 占位：调用搜索引擎 API 或爬取结果
        return []
