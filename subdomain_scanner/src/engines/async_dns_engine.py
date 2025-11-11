"""异步 DNS 引擎，使用 aiodns 进行解析验证"""
import socket
from .base_engine import BaseEngine

try:
    import aiodns
except Exception:  # 在未安装依赖时，导入会失败，保持友好降级
    aiodns = None


class AsyncDNSEngine(BaseEngine):
    def __init__(self, nameservers=None):
        if aiodns is None:
            raise RuntimeError('aiodns 未安装，请在 requirements.txt 中添加 aiodns 并安装')
        self.resolver = aiodns.DNSResolver(nameservers=nameservers)

    async def search(self, fqdn: str):
        """对 fqdn 做简单的 A 记录解析验证，解析成功则返回该域名。"""
        try:
            # family 使用 IPv4
            await self.resolver.gethostbyname(fqdn, socket.AF_INET)
            return [fqdn]
        except Exception:
            return []
