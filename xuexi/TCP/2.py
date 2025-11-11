import requests
import threading
import time
import signal
import socket
import os
import subprocess
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import urllib3

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ContentInjector:
    """内容注入器，支持多种注入攻击"""
    
    def __init__(self):
        self.injections = []
    
    def add_injection(self, injection_func):
        """添加注入函数"""
        self.injections.append(injection_func)
    
    def inject(self, content, content_type, request_info):
        """执行注入"""
        if not content_type or 'text/html' not in content_type.lower():
            return content
        
        # 解码内容
        try:
            html_content = content.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"解码内容失败: {e}")
            return content
        
        # 应用所有注入
        for injection in self.injections:
            try:
                html_content = injection(html_content, request_info)
            except Exception as e:
                print(f"注入失败: {e}")
        
        return html_content.encode('utf-8')
    
    @staticmethod
    def default_injection(html_content, request_info):
        """默认注入：在body结束前插入标记"""
        body_end = html_content.lower().find('</body>')
        if body_end != -1:
            injected_content = (
                html_content[:body_end] +
                '''<div style="position:fixed; top:20px; left:20px; background:red; color:white; padding:15px; border:3px solid yellow; z-index:9999; font-size:20px;">
                🚀 代理注入测试成功！
                </div>''' +
                html_content[body_end:]
            )
            return injected_content
        else:
            return html_content + '''
            <div style="position:fixed; top:20px; left:20px; background:red; color:white; padding:15px; border:3px solid yellow; z-index:9999; font-size:20px;">
            🚀 代理注入测试成功！
            </div>'''

class SafeRequestHandler:
    """安全的请求处理器，使用requests库并避免代理循环"""
    
    def __init__(self):
        self.session = requests.Session()
        # 关键：不信任环境变量（避免系统代理）
        self.session.trust_env = False
        self.session.proxies = {}
        
        # 设置重试策略
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def send_request(self, url, headers, method, data=None):
        """发送请求"""
        # 准备请求头
        request_headers = {k: v for k, v in headers.items() 
                         if k.lower() not in ['host', 'content-length', 'connection']}
        
        # 发送请求
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=request_headers,
                data=data,
                timeout=(3, 8),
                verify=False,
                allow_redirects=True
            )
            return response
        except requests.exceptions.RequestException as e:
            raise Exception(f"请求失败: {e}")

class ProxyRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    
    # 注入器和请求处理器作为类属性，所有实例共享
    injector = ContentInjector()
    request_handler = SafeRequestHandler()
    
    # 请求计数器
    _request_counter = 0
    _counter_lock = threading.Lock()
    
    # 添加服务器关闭标志
    _server_shutdown = False
    _shutdown_lock = threading.Lock()
    
    def __init__(self, *args, **kwargs):
        with self._counter_lock:
            ProxyRequestHandler._request_counter += 1
            self.request_id = ProxyRequestHandler._request_counter
        super().__init__(*args, **kwargs)
    
    @classmethod
    def set_server_shutdown(cls):
        """设置服务器关闭标志"""
        with cls._shutdown_lock:
            cls._server_shutdown = True
    
    @classmethod
    def should_shutdown(cls):
        """检查是否应该关闭"""
        with cls._shutdown_lock:
            return cls._server_shutdown
    
    def _build_target_url(self):
        """构建目标URL"""
        if self.path.startswith(('http://', 'https://')):
            return self.path
        
        host_header = self.headers.get('Host', '')
        if host_header:
            return f"http://{host_header}{self.path}"
        else:
            # 如果没有Host头，使用路径中的主机名（适用于绝对URI）
            parsed = urlparse(self.path)
            if parsed.netloc:
                return f"http://{parsed.netloc}{parsed.path}"
            else:
                # 无法确定目标，返回错误
                raise ValueError("无法确定目标URL")
    
    def _copy_headers(self, source_headers):
        """复制并过滤头部"""
        exclude_headers = [
            'content-length', 'transfer-encoding', 'connection', 
            'keep-alive', 'proxy-connection', 'upgrade'
        ]
        
        headers = {}
        for header, value in source_headers.items():
            if header.lower() not in exclude_headers:
                headers[header] = value
        
        # 确保有User-Agent
        if 'User-Agent' not in headers:
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            
        return headers
    
    def _handle_special_paths(self):
        """处理特殊路径"""
        if self.path == '/':
            content = '''
            <h1>代理服务器运行正常！</h1>
            <p>测试链接：</p>
            <ul>
                <li><a href="/local-test">本地测试页面</a></li>
                <li><a href="/network-test">网络连接测试</a></li>
                <li><a href="http://httpbin.org/html">httpbin.org/html</a></li>
                <li><a href="http://example.com">example.com</a></li>
            </ul>
            <p><strong>注意：</strong>如果外部网站无法访问，可能是网络策略限制。</p>
            '''
            self._send_response(200, 'text/html; charset=utf-8', content.encode('utf-8'))
            return True
            
        if self.path == '/favicon.ico':
            self._send_response(404, 'text/plain', b'Not Found')
            return True
            
        if self.path == '/status':
            content = f'{{"status": "running", "requests_handled": {ProxyRequestHandler._request_counter}}}'
            self._send_response(200, 'application/json', content.encode('utf-8'))
            return True
            
        if self.path == '/local-test':
            content = '''
            <h1>本地测试页面</h1>
            <p>这个页面完全由代理服务器生成，不依赖外部网络。</p>
            <p>如果这个页面能正常显示，说明代理服务器本身工作正常。</p>
            <div style="background:green; color:white; padding:20px; margin:10px;">
                ✅ 代理服务器工作正常！
            </div>
            '''
            self._send_response(200, 'text/html; charset=utf-8', content.encode('utf-8'))
            return True
            
        if self.path == '/network-test':
            self._test_network_connection()
            return True
            
        return False
    
    def _test_network_connection(self):
        """测试网络连接"""
        test_results = []
        
        # 测试直接socket连接
        test_hosts = [
            ('httpbin.org', 80),
            ('example.com', 80),
            ('google.com', 80),
            ('baidu.com', 80)
        ]
        
        for host, port in test_hosts:
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((host, port))
                end_time = time.time()
                sock.close()
                
                if result == 0:
                    test_results.append(f"✅ {host}:{port} - TCP连接成功 ({(end_time-start_time)*1000:.0f}ms)")
                else:
                    test_results.append(f"❌ {host}:{port} - TCP连接失败 (错误码: {result})")
                    
            except Exception as e:
                test_results.append(f"❌ {host}:{port} - 连接异常: {e}")
        
        # 测试DNS解析
        dns_hosts = ['httpbin.org', 'example.com', 'google.com', 'baidu.com']
        for host in dns_hosts:
            try:
                start_time = time.time()
                ip = socket.gethostbyname(host)
                end_time = time.time()
                test_results.append(f"✅ DNS {host} -> {ip} ({(end_time-start_time)*1000:.0f}ms)")
            except Exception as e:
                test_results.append(f"❌ DNS {host} - 解析失败: {e}")
        
        content = "<h1>网络连接测试</h1><ul>" + "".join([f"<li>{r}</li>" for r in test_results]) + "</ul>"
        self._send_response(200, 'text/html; charset=utf-8', content.encode('utf-8'))
    
    def _send_response(self, status_code, content_type, content, headers=None):
        """发送响应"""
        try:
            self.send_response(status_code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Connection', 'close')
            if headers:
                for key, value in headers.items():
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(content)
            self.wfile.flush()
        except Exception as e:
            print(f"[{self.request_id}] ❌ 发送响应失败: {e}")
        finally:
            self.close_connection = True
    
    def _handle_proxy_request(self, method):
        """处理代理请求"""
        # 检查服务器是否正在关闭
        if self.should_shutdown():
            print(f"[{self.request_id}] ⏹️ 服务器正在关闭，拒绝新请求")
            self._send_response(503, 'text/plain', b'Server is shutting down')
            return
            
        print(f"[{self.request_id}] 🔍 开始处理 {method} {self.path}")
        
        # 处理特殊路径
        if self._handle_special_paths():
            return
        
        try:
            # 构建目标URL
            target_url = self._build_target_url()
            print(f"[{self.request_id}] 🎯 目标: {target_url}")
            
            # 复制头部
            headers = self._copy_headers(self.headers)
            
            # 处理POST数据
            post_data = None
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    post_data = self.rfile.read(content_length)
            
            # 发送请求
            response = self.request_handler.send_request(target_url, headers, method, post_data)
            
            # 获取响应内容
            content = response.content
            content_type = response.headers.get('Content-Type', '')
            
            # 准备请求信息用于注入
            request_info = {
                'url': target_url,
                'method': method,
                'headers': headers,
                'request_id': self.request_id
            }
            
            # 内容注入
            content = self.injector.inject(content, content_type, request_info)
            
            # 发送响应
            response_headers = dict(response.headers)
            # 移除一些头部
            for header in ['Content-Length', 'Transfer-Encoding', 'Connection']:
                if header in response_headers:
                    del response_headers[header]
            
            self._send_response(
                response.status_code,
                content_type,
                content,
                headers=response_headers
            )
            
            print(f"[{self.request_id}] ✅ 请求处理完成")
            
        except Exception as e:
            print(f"[{self.request_id}] ❌ 处理请求失败: {e}")
            error_msg = f"代理请求失败: {str(e)}"
            self._send_response(502, 'text/plain', error_msg.encode('utf-8'))
    
    def do_GET(self):
        self._handle_proxy_request('GET')
    
    def do_POST(self):
        self._handle_proxy_request('POST')
    
    def do_HEAD(self):
        self._handle_proxy_request('HEAD')
    
    def do_CONNECT(self):
        """处理CONNECT请求（HTTPS）"""
        print(f"[{self.request_id}] ⚠️ 拒绝HTTPS请求")
        self._send_response(501, 'text/plain', b'HTTPS not supported')
    
    def log_message(self, format, *args):
        """禁用默认日志"""
        pass

class ProxyServerManager:
    """代理服务器管理器"""
    
    def __init__(self, port=8080):
        self.port = port
        self.httpd = None
        self.shutdown_event = threading.Event()
        self.force_shutdown = False
    
    def cleanup_ports(self):
        """清理占用端口"""
        try:
            print(f"🔄 清理端口 {self.port}...")
            if os.name == 'nt':  # Windows
                # 使用netstat和taskkill
                result = subprocess.run(
                    f'netstat -ano | findstr :{self.port}', 
                    shell=True, capture_output=True, text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        parts = line.split()
                        if len(parts) >= 5:
                            pid = parts[-1]
                            subprocess.run(f'taskkill /F /PID {pid}', shell=True, 
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:  # Linux/Mac
                subprocess.run(
                    f'fuser -k {self.port}/tcp 2>/dev/null', 
                    shell=True
                )
            time.sleep(2)
        except Exception as e:
            print(f"清理端口警告: {e}")
    
    def signal_handler(self, signum, frame):
        """信号处理"""
        print(f"\n🛑 收到信号 {signum}，正在停止服务器...")
        
        if self.force_shutdown:
            print("💥 强制退出...")
            os._exit(1)
            
        self.force_shutdown = True
        self.shutdown_event.set()
        
        # 设置请求处理器的关闭标志
        ProxyRequestHandler.set_server_shutdown()
        
        self.cleanup_resources()
        print("✅ 服务器已停止")
        
        # 如果3秒后还在运行，强制退出
        threading.Timer(3.0, self._force_exit).start()
    
    def _force_exit(self):
        """强制退出"""
        if threading.main_thread().is_alive():
            print("💥 优雅关闭超时，强制退出...")
            os._exit(1)
    
    def cleanup_resources(self):
        """清理资源"""
        if self.httpd:
            print("🧹 清理资源...")
            try:
                # 先关闭socket以避免新连接
                if hasattr(self.httpd, 'socket') and self.httpd.socket:
                    try:
                        self.httpd.socket.close()
                    except:
                        pass
                
                # 然后关闭服务器
                self.httpd.shutdown()
                self.httpd.server_close()
                self.httpd = None
                
                # 关闭请求会话
                ProxyRequestHandler.request_handler.session.close()
                
            except Exception as e:
                print(f"清理资源失败: {e}")
    
    def run(self):
        """运行代理服务器"""
        self.cleanup_ports()
        
        # 注册信号处理器
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            server_address = ('', self.port)
            
            # 创建自定义的ThreadingHTTPServer，设置线程为daemon
            class DaemonThreadingHTTPServer(ThreadingHTTPServer):
                def process_request(self, request, client_address):
                    # 创建daemon线程处理请求
                    t = threading.Thread(target=self.process_request_thread,
                                       args=(request, client_address),
                                       daemon=True)
                    t.start()
            
            self.httpd = DaemonThreadingHTTPServer(server_address, ProxyRequestHandler)
            self.httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.httpd.timeout = 0.5  # 设置更短的超时以便更频繁检查关闭事件
            
            print(f"🚀 代理服务器启动: http://127.0.0.1:{self.port}")
            print("📝 测试步骤:")
            print("  1. 访问 http://127.0.0.1:8080/local-test (测试代理服务器本身)")
            print("  2. 访问 http://127.0.0.1:8080/network-test (测试网络连接)")
            print("  3. 在浏览器中设置系统代理为 127.0.0.1:8080")
            print("  4. 访问任意HTTP网站测试注入")
            print("⚠️  注意: 本代理不支持HTTPS")
            print("⏹️  Ctrl+C 停止")
            print("-" * 50)
            
            while not self.shutdown_event.is_set():
                try:
                    self.httpd.handle_request()
                except socket.timeout:
                    continue
                except Exception as e:
                    if not self.shutdown_event.is_set():
                        print(f"处理请求异常: {e}")
            
        except Exception as e:
            if not self.shutdown_event.is_set():
                print(f"💥 启动失败: {e}")
        finally:
            self.cleanup_resources()

if __name__ == '__main__':
    # 添加默认注入
    ProxyRequestHandler.injector.add_injection(ContentInjector.default_injection)
    
    print("启动增强版HTTP代理服务器...")
    try:
        proxy_manager = ProxyServerManager(8080)
        proxy_manager.run()
    except KeyboardInterrupt:
        print("\n用户中断")
    except Exception as e:
        print(f"服务器异常: {e}")