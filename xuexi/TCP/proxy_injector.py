from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request

class InjectProxy(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            # 构建目标URL - 直接使用绝对URL
            if self.path.startswith('/'):
                # 如果是路径形式，转换为完整URL
                target_url = f"http://httpbin.org{self.path}"
            else:
                target_url = self.path
                
            print(f"正在访问: {target_url}")
            
            # 创建请求
            req = urllib.request.Request(
                target_url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            
            # 获取响应
            resp = urllib.request.urlopen(req)
            content = resp.read()
            content_type = resp.headers.get('Content-Type', '')
            
            print(f"内容类型: {content_type}")
            
            # HTML内容注入
            if "text/html" in content_type.lower():
                try:
                    html_content = content.decode('utf-8')
                    print("检测到HTML内容，进行注入...")
                    
                    # 注入明显的标记
                    injected_content = html_content.replace(
                        '</body>', 
                        '''<div style="position:fixed; top:20px; left:20px; background:red; color:white; padding:15px; border:3px solid yellow; z-index:9999; font-size:20px;">
                           🚀 代理注入测试成功！
                           </div></body>'''
                    )
                    content = injected_content.encode('utf-8')
                    print("✅ 内容注入完成")
                except Exception as e:
                    print(f"注入失败: {e}")
            
            # 发送响应
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            
        except Exception as e:
            print(f"错误: {e}")
            self.send_error(500, f"代理错误: {str(e)}")

def run_proxy(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, InjectProxy)
    print(f"🔌 代理服务器启动在: http://127.0.0.1:{port}")
    print("📝 测试命令: curl -x http://127.0.0.1:8080 http://httpbin.org/html")
    print("⏹️  按 Ctrl+C 停止")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 停止代理服务器")

if __name__ == '__main__':
    run_proxy(8080) 