"""引擎基类：定义引擎接口"""
from abc import ABC, abstractmethod

class BaseEngine(ABC):
    @abstractmethod
    def search(self, target: str):
        """返回发现的子域名列表或可迭代对象"""
        pass
