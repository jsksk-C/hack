"""
Selenium JS POST demo

说明：
- 该脚本演示如何用 Selenium 在浏览器上下文执行一段 JS（fetch）来向
  https://jsonplaceholder.typicode.com/posts 发起 POST 请求，从而演示“在浏览器执行 JS 的 POST 流程”。
- jsonplaceholder.typicode.com 是一个公开的测试 REST API；POST 会返回示例响应（通常为 201）。

使用说明：
- 需要安装 selenium：
    pip install selenium
- 需要浏览器驱动（例如 chromedriver）。你可以手动安装 chromedriver 并把可执行文件放在 PATH，
  或使用 webdriver-manager（pip install webdriver-manager）来自动管理驱动。

该文件仅作演示；在无浏览器或无驱动的环境中运行会报错。
"""

import json
import time

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
except Exception:
    webdriver = None


def js_post_via_browser(driver, url, payload, timeout=10):
    """在浏览器上下文用 fetch 发起 POST 并返回解析后的结果。

    使用 execute_async_script 来等待 fetch 完成并把结果返回给 Python。
    返回 dict：{ 'status': int, 'body': dict } 或 { 'error': '...' }
    """
    script = '''
    const url = arguments[0];
    const payload = arguments[1];
    const callback = arguments[arguments.length - 1];
    fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json; charset=UTF-8'},
      body: JSON.stringify(payload)
    })
    .then(async (resp) => {
        let bodyText = null;
        try { bodyText = await resp.text(); } catch(e) { bodyText = null; }
        let parsed = null;
        try { parsed = bodyText ? JSON.parse(bodyText) : null; } catch(e) { parsed = bodyText; }
        callback({status: resp.status, body: parsed});
    })
    .catch((e) => callback({error: e.toString()}));
    '''

    # execute_async_script will wait until callback is invoked
    return driver.execute_async_script(script, url, payload)


def demo_with_chrome(url='https://jsonplaceholder.typicode.com/posts'):
    if webdriver is None:
        print('selenium not available. Install with: pip install selenium')
        return

    # Try to start Chrome (assumes chromedriver is in PATH)
    try:
        # You can customize Service(...) 指向具体 chromedriver 路径
        service = Service()
        options = webdriver.ChromeOptions()
        options.add_argument('--headless=new')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-gpu')
        driver = webdriver.Chrome(service=service, options=options)
    except Exception as e:
        print('Failed to start Chrome webdriver:', e)
        print('If you want automatic driver management, install webdriver-manager and adapt this script.')
        return

    try:
        driver.set_page_load_timeout(10)
        # open a blank page then execute fetch in page context
        driver.get('about:blank')
        payload = { 'title': 'foo', 'body': 'bar', 'userId': 1 }
        print('Executing JS fetch POST to', url)
        result = js_post_via_browser(driver, url, payload)
        print('Result from browser fetch:')
        print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        try:
            driver.quit()
        except Exception:
            pass


if __name__ == '__main__':
    print('Selenium JS POST demo (jsonplaceholder)')
    print('Note: this demo requires Selenium and a browser driver (chromedriver).')
    demo_with_chrome()
