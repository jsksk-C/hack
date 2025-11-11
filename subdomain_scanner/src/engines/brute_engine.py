"""字典爆破引擎：对目标进行前缀/子域名爆破（最小实现）"""
from .base_engine import BaseEngine
from pathlib import Path

class BruteEngine(BaseEngine):
    def __init__(self, wordlist_path=None):
        self.wordlist_path = Path(wordlist_path) if wordlist_path else Path(__file__).parents[2] / 'data' / 'subdomains.txt'

    def search(self, target: str):
        out = []
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    sub = line.strip()
                    if not sub:
                        continue
                    out.append(f"{sub}.{target}")
        except Exception:
            return []
        return out
