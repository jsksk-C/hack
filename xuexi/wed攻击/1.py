# get网页内容
import urllib.parse
import urllib.request
url = 'http://www.example.com'
with urllib.request.urlopen(url) as response:
    content = response.read()
   
print(content.decode('utf-8'))