import requests

proxies = {
    'http': '219.251.142.189:3128',
    'https': '219.251.142.189:3128'
}
resp = requests.get('https://httpbin.org/ip', proxies=proxies, timeout=5)
print(resp.json())          # 🎉 验证 IP 是否生效