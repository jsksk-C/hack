"""扫描器核心调度（最小可运行骨架）"""
from typing import List

class SubdomainScanner:
    """简单的子域名扫描器骨架。后续会注入不同引擎。"""

    def __init__(self, config, engines: List[object]=None):
        self.config = config
        self.engines = engines or []

    def register_engine(self, engine):
        self.engines.append(engine)

    def run(self, target: str):
        """运行所有引擎并汇总结果（同步版）"""
        results = []
        for engine in self.engines:
            try:
                res = engine.search(target)
                if res:
                    results.extend(res)
            except Exception as e:
                # 简单容错，后续用 logger 记录
                print(f"Engine {engine} error: {e}")
        return list(sorted(set(results)))
