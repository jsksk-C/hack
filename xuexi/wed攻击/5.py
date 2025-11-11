# 获取Cookie（可选），准备并发送POST请求
"""
使用 requests.Session 先 GET（获取 cookie），再 POST 的示例。

说明：
- 函数 post_with_session 会使用会话（session）并设置常见浏览器 headers。
- 默认会先发一次 GET 来获取 cookie（use_get_cookie=True），然后再 POST。
- 如果 POST 返回 403 并且 URL 是 http://，会尝试 https:// 回退一次。

脚本末尾演示使用 https://httpbin.org/post 来验证成功（避免对 example.com 直接请求导致 403）。
"""

from typing import Dict, Optional
import time
import requests
from urllib.parse import urlparse


def post_with_session(url: str, data: Dict[str, str], headers: Optional[Dict[str, str]] = None,
                      use_get_cookie: bool = True, max_retries: int = 3, timeout: int = 10,
                      debug: bool = False):
    """Use requests.Session to GET (to set cookies) and then POST form data.

    Returns the Response object on success, or None on failure.
    """
    session = requests.Session()

    # sensible default headers like a real browser
    default_headers = {
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                       'Chrome/91.0.4472.124 Safari/537.36'),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        # Content-Type will be set by requests when using `data=` for form
    }
    if headers:
        default_headers.update(headers)

    session.headers.update(default_headers)

    parsed = urlparse(url)
    host_root = f"{parsed.scheme}://{parsed.netloc}"

    attempt = 0
    while attempt < max_retries:
        attempt += 1
        try:
            # optional GET to obtain cookies / session state
            if use_get_cookie:
                try:
                    get_resp = session.get(host_root, timeout=timeout)
                    if debug:
                        print('--- GET to host root ---')
                        print(f'GET {host_root} -> {get_resp.status_code}')
                        print('Cookies after GET:', session.cookies.get_dict())
                except Exception as e:
                    if debug:
                        print(f'GET error (ignored): {e}')

            # prepare request so we can show prepared headers/body when debug=True
            req_obj = requests.Request('POST', url, data=data)
            prepared = session.prepare_request(req_obj)
            if debug:
                print('--- Prepared request preview ---')
                # show headers that will be sent
                for k, v in prepared.headers.items():
                    print(f'{k}: {v}')
                body = prepared.body or b''
                try:
                    # prepared.body may be bytes or str
                    if isinstance(body, bytes):
                        print('\nBody (preview):', body[:1000])
                    else:
                        print('\nBody (preview):', str(body)[:1000])
                except Exception:
                    print('\nBody: <could not decode>')

            resp = session.send(prepared, timeout=timeout)

            if resp.status_code == 200:
                if debug:
                    print('--- Response debug info ---')
                    print('Status:', resp.status_code)
                    print('Response headers:')
                    for k, v in resp.headers.items():
                        print(f'  {k}: {v}')
                    print('Response cookies:', resp.cookies.get_dict())
                    if resp.history:
                        print('Redirect history:')
                        for h in resp.history:
                            print(f'  {h.status_code} -> {h.url}')
                print(f"HTTP 200 - received {len(resp.content)} bytes")
                print(resp.text[:2000])
                return resp

            # handle 403: try https fallback if http
            if resp.status_code == 403 and url.startswith('http://'):
                print(f"HTTP 403 on attempt {attempt}. Trying HTTPS fallback.")
                url = 'https://' + url[len('http://'):]
                parsed = urlparse(url)
                host_root = f"{parsed.scheme}://{parsed.netloc}"
                # small delay then retry
                time.sleep(1)
                continue

            # if not success and not 403, may retry
            print(f"HTTP {resp.status_code}: {resp.reason}")
            if debug:
                print('--- Response body preview ---')
                print(resp.text[:1000])
            if attempt < max_retries:
                time.sleep(0.8 * attempt)
                continue
            return resp

        except requests.RequestException as e:
            print(f"Request error on attempt {attempt}: {e}")
            if attempt < max_retries:
                time.sleep(0.8 * attempt)
                continue
            return None


if __name__ == '__main__':
    # target you want to POST to (change to your real target when ready)
    target_url = 'http://www.example.com/form'  # keep as placeholder

    # demo_url 用于验证脚本能成功运行（不被 403 阻止）
    demo_url = 'https://httpbin.org/post'

    info = {'name': 'Alice', 'age': '30'}

    extra_headers = {
        'Referer': 'https://httpbin.org/',
    }

    print('--- demo POST to httpbin.org (验证) ---')
    post_with_session(demo_url, info, headers=extra_headers)

    print('\n--- 若要测试真实目标，将 demo_url 替换为 target_url 或直接修改脚本变量 ---')