"""异步扫描器核心：支持同时运行同步或异步引擎"""
import asyncio
import inspect
from typing import List


class AsyncSubdomainScanner:
    """Async 子域名扫描调度器。

    engines 中可以混合同步引擎（实现 search(target) 同步方法）
    或异步引擎（实现 async def search(target)）。

    支持通过配置项 `concurrency` 限制并发量（默认 20）。
    """

    def __init__(self, config, engines: List[object] = None):
        self.config = config
        self.engines = engines or []
        # 从配置读取并发限制
        self._concurrency = 20
        try:
            if config is not None:
                self._concurrency = int(config.get('concurrency', self._concurrency))
        except Exception:
            pass

    def register_engine(self, engine):
        self.engines.append(engine)

    async def _wrap_call(self, engine, target, sem: asyncio.Semaphore):
        """包装器：在信号量下调用引擎的 search（支持 sync/async）。"""
        search = getattr(engine, 'search', None)
        if search is None:
            return []

        async with sem:
            try:
                if inspect.iscoroutinefunction(search):
                    return await search(target)
                else:
                    loop = asyncio.get_running_loop()
                    return await loop.run_in_executor(None, search, target)
            except Exception as e:
                # 简单容错，后续使用 logger 记录
                print(f"Engine {engine.__class__.__name__} error: {e}")
                return []

    async def run(self, target: str):
        """并发运行所有引擎并汇总去重结果。

        返回字符串列表。
        """
        sem = asyncio.Semaphore(self._concurrency)
        tasks = [self._wrap_call(engine, target, sem) for engine in self.engines]

        results = []
        if tasks:
            gathered = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            gathered = []

        for item in gathered:
            if isinstance(item, Exception):
                print(f"Engine raised: {item}")
            elif item:
                try:
                    results.extend(item)
                except TypeError:
                    # 若 engine 返回单个字符串，直接添加
                    results.append(item)

        return sorted(set(results))

