"""DNS 解析工具（使用 dnspython）"""
import dns.resolver

def resolve(name: str, record_type='A', nameservers=None):
    r = dns.resolver.Resolver()
    if nameservers:
        r.nameservers = nameservers
    try:
        answers = r.resolve(name, record_type)
        return [str(x) for x in answers]
    except Exception:
        return []
