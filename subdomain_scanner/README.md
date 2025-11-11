# subdomain_scanner

一个轻量的子域名扫描器项目骨架，包含多引擎设计。此仓库为起点，包含：

- core: 调度与结果管理
- engines: DNS、证书、搜索等引擎（占位实现）
- utils: DNS 解析、HTTP 客户端、日志
- output: 导出为 JSON/CSV/HTML

快速开始

1. 创建虚拟环境并安装依赖：

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2. 运行：

```bash
python main.py example.com
```
 
Asynchronous scanner
--------------------

This project includes an asynchronous runner `main_async.py` and `main.py` also supports an `--async` flag to use the async scanner.

Usage (using project venv on Windows cmd.exe):

```cmd
cd /d d:\Defense\PyHack-Lab\subdomain_scanner
D:\Defense\PyHack-Lab\venv\python.exe main_async.py example.com -o results.json
```

Or use the unified `main.py` with `--async`:

```cmd
D:\Defense\PyHack-Lab\venv\python.exe main.py --async example.com -o results_async.json
```

CLI options
- `target` (positional): domain to scan, e.g. `example.com`
- `-o, --output`: output JSON file path (if omitted the results are printed)
- `-c, --concurrency`: override concurrency limit from config
- `--async`: use the asynchronous scanner (uses `aiodns` if available for DNS validation)

Notes & troubleshooting
- `aiodns` is optional; if unavailable the async DNS engine will fail to initialize and the scanner will fall back to brute-only behavior.
- On Windows, installing `aiodns` may require a binary wheel or build tools; if you have trouble, use the sync DNS engine or create a venv with a Python distribution that has wheels available.
- `cert_engine` and `search_engine` are placeholders; they currently return no results. You can extend them to call crt.sh, Censys, or search APIs.

Output
- JSON exporter writes a simple list of discovered subdomains. You can add CSV/HTML export via the `src/output` exporters.

