"""程序入口：支持同步与异步两种运行模式（使用 --async 开关）。

示例：
  python main.py example.com
  python main.py --async example.com -o results.json
"""
import sys
import argparse

from src.core.config import Config
from src.core.result_manager import ResultManager
from src.output.json_exporter import JsonExporter

def _run_sync(target, config, output):
    from src.core.scanner import SubdomainScanner
    from src.engines.brute_engine import BruteEngine
    from src.engines.dns_engine import DNSEngine

    brute = BruteEngine(wordlist_path=config.get('wordlist'))
    dns = DNSEngine(nameservers=config.get('nameservers'))
    scanner = SubdomainScanner(config)
    scanner.register_engine(brute)
    scanner.register_engine(dns)

    results = scanner.run(target)
    rm = ResultManager()
    rm.add(results)

    if output:
        JsonExporter().export(rm.get_all(), output)
        print(f"已导出 {len(rm.get_all())} 个子域到 {output}")
    else:
        for r in rm.get_all():
            print(r)


def _run_async(target, config, output):
    # 异步入口按需导入，避免缺少依赖导致模块级导入失败
    try:
        from src.core.scanner_async import AsyncSubdomainScanner
        from src.engines.async_brute_engine import AsyncBruteEngine
        from src.engines.async_dns_engine import AsyncDNSEngine
    except Exception as e:
        print(f"无法导入异步模块: {e}. 确认依赖已安装。")
        return

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

    import asyncio
    results = asyncio.run(scanner.run(target))
    rm = ResultManager()
    rm.add(results)

    if output:
        JsonExporter().export(rm.get_all(), output)
        print(f"已导出 {len(rm.get_all())} 个子域到 {output}")
    else:
        for r in rm.get_all():
            print(r)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Subdomain scanner (sync + async)')
    parser.add_argument('target', help='Target domain, e.g. example.com')
    parser.add_argument('--async', dest='use_async', action='store_true', help='Use async scanner')
    parser.add_argument('--output', '-o', help='Output JSON path', default=None)
    parser.add_argument('--concurrency', '-c', type=int, help='Concurrency limit', default=None)

    if argv is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(argv)

    config = Config()
    if args.concurrency is not None:
        cfg = config.as_dict()
        cfg['concurrency'] = args.concurrency
        config._data = cfg

    target = args.target.strip()

    if args.use_async:
        _run_async(target, config, args.output)
    else:
        _run_sync(target, config, args.output)


if __name__ == '__main__':
    raise SystemExit(main())
