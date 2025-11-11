"""结果管理：简单封装用于存储与导出结果的类"""
from typing import Iterable

class ResultManager:
    def __init__(self):
        self._results = set()

    def add(self, items: Iterable[str]):
        for it in items:
            self._results.add(it)

    def get_all(self):
        return sorted(self._results)

    def clear(self):
        self._results.clear()
