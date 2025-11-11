"""异步入口示例：使用 AsyncSubdomainScanner、AsyncBruteEngine 与 AsyncDNSEngine"""
import sys
import asyncio
import argparse

from src.core.config import Config
from src.core.scanner_async import AsyncSubdomainScanner
from src.engines.async_brute_engine import AsyncBruteEngine
from src.engines.async_dns_engine import AsyncDNSEngine
from src.core.result_manager import ResultManager
from src.output.json_exporter import JsonExporter


def main(argv=None):
    parser = argparse.ArgumentParser(description='Async Subdomain Scanner')
    parser.add_argument('target', help='Target domain, e.g. example.com')
    parser.add_argument('--output', '-o', help='Output path (json)', default=None)
    parser.add_argument('--concurrency', '-c', type=int, help='Concurrency limit', default=None)
    if argv is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(argv)

    config = Config()
    if args.concurrency is not None:
        # 覆盖配置中的并发
        # Config 实现简单，直接注入到字典返回值以被 AsyncSubdomainScanner 读取
        cfg = config.as_dict()
        cfg['concurrency'] = args.concurrency
        config._data = cfg

    target = args.target.strip()

    brute = AsyncBruteEngine(wordlist_path=config.get('wordlist'))
    dns = None
    try:
        dns = AsyncDNSEngine(nameservers=config.get('nameservers'))
    except RuntimeError as e:
        print(f"Async DNSEngine 初始化失败: {e}")

    scanner = AsyncSubdomainScanner(config)
    scanner.register_engine(brute)
    if dns:
        scanner.register_engine(dns)

    results = asyncio.run(scanner.run(target))

    rm = ResultManager()
    rm.add(results)

    if args.output:
        exporter = JsonExporter()
        exporter.export(rm.get_all(), args.output)
        print(f"已导出 {len(rm.get_all())} 个子域到 {args.output}")
    else:
        for r in rm.get_all():
            print(r)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
