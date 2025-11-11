import requests
import json

def simple_post_demo(url='https://jsonplaceholder.typicode.com/posts'):
    """使用 requests 库发送 POST 请求"""
    try:
        payload = {'title': 'foo', 'body': 'bar', 'userId': 1}
        headers = {'Content-Type': 'application/json; charset=UTF-8'}
        
        print(f'Sending POST request to {url}')
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        
        print(f'Status Code: {response.status_code}')
        print('Response:')
        print(json.dumps(response.json(), indent=2, ensure_ascii=False))
        
    except requests.exceptions.RequestException as e:
        print(f'Request failed: {e}')
    except json.JSONDecodeError as e:
        print(f'JSON decode error: {e}')
        print(f'Raw response: {response.text}')

if __name__ == '__main__':
    print('Simple POST demo with requests library')
    simple_post_demo()