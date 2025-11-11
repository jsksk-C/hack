"""简易 HTTP 客户端封装（requests 协议）"""
import requests

class HttpClient:
    def __init__(self, timeout=10):
        self.session = requests.Session()
        self.timeout = timeout

    def get(self, url, **kwargs):
        return self.session.get(url, timeout=self.timeout, **kwargs)

    def close(self):
        self.session.close()
