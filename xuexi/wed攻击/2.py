# post请求
import urllib.parse
import urllib.request

info = {'name': 'Alice',
'age': 30}
url = 'http://httpbin.org/post'

data = urllib.parse.urlencode(info).encode('utf-8')

rep = urllib.request.Request(url, data)
with urllib.request.urlopen(rep) as response:
    content = response.read()

print(content.decode('utf-8'))