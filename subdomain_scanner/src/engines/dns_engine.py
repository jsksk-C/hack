"""DNS 查询引擎（同步、基础）"""
import dns.resolver
from .base_engine import BaseEngine

class DNSEngine(BaseEngine):
    def __init__(self, nameservers=None):
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers

    def search(self, target: str):
        # 本引擎期望接收一个待查询的子域名字符串，例如 'www.example.com'
        try:
            answers = self.resolver.resolve(target, 'A')
            return [str(target)]
        except Exception:
            return []
