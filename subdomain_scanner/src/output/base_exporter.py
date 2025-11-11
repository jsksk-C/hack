"""导出器基类"""
from abc import ABC, abstractmethod

class BaseExporter(ABC):
    @abstractmethod
    def export(self, items, path):
        pass
