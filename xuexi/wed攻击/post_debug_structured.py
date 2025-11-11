"""
Structured debug POST helper using requests.Session。

功能：
- post_with_session_structured 会执行可选的 GET(获取 cookie)，构造并准备 POST 请求，发送请求并返回结构化的调试信息（dict）。
- 返回字段包括：prepared_headers、prepared_body、cookies_before、cookies_after、response_status、response_headers、response_body_preview、redirect_history、attempted_urls。

演示：__main__ 会向 https://jsonplaceholder.typicode.com/posts 发起 POST，并打印结构化结果。
"""

from typing import Dict, Optional, Any
import time
import requests
from urllib.parse import urlparse
import json


def post_with_session_structured(url: str, data: Dict[str, Any], headers: Optional[Dict[str, str]] = None,
                                 use_get_cookie: bool = True, max_retries: int = 3, timeout: int = 10) -> Dict[str, Any]:
    session = requests.Session()

    default_headers = {
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                       'Chrome/91.0.4472.124 Safari/537.36'),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }
    if headers:
        default_headers.update(headers)
    session.headers.update(default_headers)

    parsed = urlparse(url)
    host_root = f"{parsed.scheme}://{parsed.netloc}"

    attempted_urls = []
    attempt = 0
    last_exc = None

    # container for debug data
    debug: Dict[str, Any] = {
        'attempts': [],
        'final': None,
    }

    while attempt < max_retries:
        attempt += 1
        attempt_record: Dict[str, Any] = {'attempt': attempt}
        try:
            cookies_before = session.cookies.get_dict()
            attempt_record['cookies_before'] = cookies_before

            if use_get_cookie:
                try:
                    get_resp = session.get(host_root, timeout=timeout)
                    attempt_record['get_status'] = get_resp.status_code
                    attempt_record['cookies_after_get'] = session.cookies.get_dict()
                except Exception as e:
                    attempt_record['get_error'] = str(e)

            # prepare request
            req_obj = requests.Request('POST', url, data=data)
            prepared = session.prepare_request(req_obj)

            attempt_record['prepared_headers'] = dict(prepared.headers)
            # body preview
            body_preview = None
            try:
                b = prepared.body or b''
                if isinstance(b, bytes):
                    body_preview = b.decode('utf-8', errors='replace')[:2000]
                else:
                    body_preview = str(b)[:2000]
            except Exception:
                body_preview = '<unable to decode body>'
            attempt_record['prepared_body_preview'] = body_preview

            attempted_urls.append(prepared.url)

            # send
            resp = session.send(prepared, timeout=timeout)

            attempt_record['response_status'] = resp.status_code
            attempt_record['response_headers'] = dict(resp.headers)
            # response body preview
            try:
                attempt_record['response_body_preview'] = resp.text[:2000]
            except Exception:
                attempt_record['response_body_preview'] = '<binary or unreadable>'

            attempt_record['cookies_after'] = session.cookies.get_dict()

            # redirect history
            attempt_record['redirect_history'] = [{'status_code': h.status_code, 'url': h.url} for h in resp.history]

            debug['attempts'].append(attempt_record)

            # success
            debug['final'] = {
                'status': resp.status_code,
                'url': resp.url,
            }
            debug['attempted_urls'] = attempted_urls
            return debug

        except requests.RequestException as e:
            last_exc = e
            attempt_record['exception'] = str(e)
            debug['attempts'].append(attempt_record)
            if attempt < max_retries:
                time.sleep(0.8 * attempt)
                continue
            break

    # if we get here, failed
    debug['error'] = str(last_exc)
    debug['attempted_urls'] = attempted_urls
    return debug


if __name__ == '__main__':
    demo_url = 'https://jsonplaceholder.typicode.com/posts'
    info = { 'title': 'foo', 'body': 'bar', 'userId': 1 }
    print('Demo structured POST to', demo_url)
    result = post_with_session_structured(demo_url, info, headers={'Referer': 'https://jsonplaceholder.typicode.com/'})
    print(json.dumps(result, indent=2, ensure_ascii=False))
