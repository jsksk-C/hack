"""异步暴力字典引擎（最小实现）

此引擎本身为异步接口，但读取字典在初始化时同步进行以简化实现。
"""
from pathlib import Path
from .base_engine import BaseEngine


class AsyncBruteEngine(BaseEngine):
    def __init__(self, wordlist_path=None):
        self.wordlist_path = Path(wordlist_path) if wordlist_path else Path(__file__).parents[2] / 'data' / 'subdomains.txt'
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                self.words = [l.strip() for l in f if l.strip()]
        except Exception:
            self.words = []

    async def search(self, target: str):
        # 返回候选子域（不在此处做解析验证）
        return [f"{w}.{target}" for w in self.words]
