# 完整的POST请求示例，包含详细的请求头信息 （请求头）

import urllib.request
import urllib.parse

# 目标URL - 这里用一个真实的测试网站
url = 'https://httpbin.org/post'  # 这是一个用于测试HTTP请求的网站

# 准备数据
info = {'name': 'Alice', 'age': 30, 'city': 'Beijing'}
data = urllib.parse.urlencode(info).encode('utf-8')

# 完整的请求头模拟真实浏览器
headers = {
    # User-Agent: 告诉服务器客户端是什么浏览器和操作系统
    # 这是最重要的反爬虫标识
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    
    # Content-Type: 告诉服务器请求体的格式
    # application/x-www-form-urlencoded 表示表单数据
    'Content-Type': 'application/x-www-form-urlencoded',
    
    # Accept: 告诉服务器客户端能接收什么类型的响应
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    
    # Accept-Language: 告诉服务器客户端的语言偏好
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    
    # Accept-Encoding: 告诉服务器客户端支持的压缩格式
    'Accept-Encoding': 'gzip, deflate, br',
    
    # Connection: 控制网络连接是否保持
    'Connection': 'keep-alive',
    
    # Referer: 告诉服务器请求是从哪个页面跳转过来的
    # 很多网站会检查这个头来防止盗链
    'Referer': 'https://httpbin.org/',
    
    # Origin: 告诉服务器请求的来源（用于CORS跨域请求）
    'Origin': 'https://httpbin.org',
    
    # Sec-Fetch-* 系列头：现代浏览器新增的安全头
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    
    # Upgrade-Insecure-Requests: 告诉服务器愿意升级到HTTPS
    'Upgrade-Insecure-Requests': '1',
    
    # Cache-Control: 控制缓存行为
    'Cache-Control': 'max-age=0'
}

# 创建请求对象
req = urllib.request.Request(url, data=data, headers=headers)

try:
    # 发送请求
    with urllib.request.urlopen(req) as response:
        content = response.read().decode('utf-8')
        print("请求成功！")
        print("状态码:", response.status)
        print("响应内容:")
        print(content)
        
except urllib.error.HTTPError as e:
    print(f"HTTP错误 {e.code}: {e.reason}")
    # 尝试读取错误响应内容
    try:
        error_content = e.read().decode('utf-8')
        print("错误响应:", error_content)
    except:
        pass
    
except Exception as e:
    print(f"其他错误: {e}")

"""
## 请求头详细作用说明：

### 1. **User-Agent** (最重要)
- **作用**: 标识客户端类型
- **为什么重要**: 很多网站会拒绝没有User-Agent或使用脚本默认User-Agent的请求
- **示例**: `Mozilla/5.0...` 表示Chrome浏览器在Windows上

### 2. **Content-Type**
- **作用**: 定义请求体的格式
- **表单提交**: `application/x-www-form-urlencoded`
- **JSON数据**: `application/json`
- **文件上传**: `multipart/form-data`

### 3. **Accept 系列**
- `Accept`: 客户端能处理的响应类型
- `Accept-Language`: 语言偏好
- `Accept-Encoding`: 支持的压缩格式

### 4. **Referer**
- **作用**: 告诉服务器请求来源页面
- **反爬虫**: 很多网站检查这个头来防止外部直接访问

### 5. **Cookie** (需要时添加)
```python
# 如果需要添加Cookie
headers['Cookie'] = 'session_id=abc123; user_token=xyz456'
```

"""