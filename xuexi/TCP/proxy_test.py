import requests
import threading
import time
import signal
import sys
import socket
import os
import subprocess
import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from typing import Dict, List, Callable, Any, Optional
import urllib3
import hashlib
from concurrent.futures import ThreadPoolExecutor
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('proxy_server.log', encoding='utf-8')
    ]
)
logger = logging.getLogger('WinEdgeProxy')

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class InjectionEngine:
    """
    注入引擎 - 支持多种注入攻击的模块化系统
    """
    
    def __init__(self):
        self.injections: Dict[str, Callable] = {}
        self.enabled_injections: List[str] = []
        self.injection_config: Dict[str, Any] = {}
        
        # 注册默认注入
        self._register_default_injections()
    
    def _register_default_injections(self):
        """注册默认注入方法"""
        self.register_injection('html_banner', self._html_banner_injection)
        self.register_injection('xss_test', self._xss_test_injection)
        self.register_injection('beacon', self._beacon_injection)
    
    def register_injection(self, name: str, injection_func: Callable):
        """注册新的注入方法"""
        self.injections[name] = injection_func
        logger.info(f"注册注入方法: {name}")
    
    def enable_injection(self, name: str, config: Dict = None):
        """启用指定的注入方法"""
        if name not in self.injections:
            logger.warning(f"未知的注入方法: {name}")
            return False
        
        if name not in self.enabled_injections:
            self.enabled_injections.append(name)
        
        if config:
            self.injection_config[name] = config
        elif name not in self.injection_config:
            self.injection_config[name] = {}
        
        logger.info(f"启用注入方法: {name}")
        return True
    
    def disable_injection(self, name: str):
        """禁用指定的注入方法"""
        if name in self.enabled_injections:
            self.enabled_injections.remove(name)
            logger.info(f"禁用注入方法: {name}")
            return True
        return False
    
    def inject(self, content: bytes, content_type: str, request_info: Dict) -> bytes:
        """执行所有启用的注入"""
        if not content or not content_type or 'text/html' not in content_type.lower():
            return content
        
        try:
            # 解码HTML内容
            html_content = content.decode('utf-8', errors='ignore')
            original_content = html_content
            
            # 应用所有启用的注入
            for injection_name in self.enabled_injections:
                if injection_name in self.injections:
                    try:
                        html_content = self.injections[injection_name](
                            html_content, 
                            request_info,
                            self.injection_config.get(injection_name, {})
                        )
                        logger.debug(f"应用注入: {injection_name}")
                    except Exception as e:
                        logger.error(f"注入 {injection_name} 失败: {e}")
            
            # 如果内容被修改，重新编码
            if html_content != original_content:
                return html_content.encode('utf-8')
            
            return content
            
        except Exception as e:
            logger.error(f"注入过程出错: {e}")
            return content
    
    def _html_banner_injection(self, html_content: str, request_info: Dict, config: Dict) -> str:
        """HTML横幅注入"""
        banner_text = config.get('text', '🚀 代理注入测试成功！')
        banner_style = config.get('style', '''
            position:fixed; 
            top:20px; 
            left:20px; 
            background:red; 
            color:white; 
            padding:15px; 
            border:3px solid yellow; 
            z-index:9999; 
            font-size:20px;
            font-family: Arial, sans-serif;
        ''')
        
        injection_html = f'''
        <div style="{banner_style}">
            {banner_text} 
            <small>(请求ID: {request_info.get('request_id', 'N/A')})</small>
        </div>
        '''
        
        # 在body结束前插入
        body_end = html_content.lower().find('</body>')
        if body_end != -1:
            return html_content[:body_end] + injection_html + html_content[body_end:]
        else:
            return html_content + injection_html
    
    def _xss_test_injection(self, html_content: str, request_info: Dict, config: Dict) -> str:
        """XSS测试注入"""
        test_payload = config.get('payload', 'alert("XSS Test - Safe")')
        
        xss_script = f'''
        <script>
        // 安全的XSS测试
        if (window.console && console.log) {{
            console.log("XSS测试注入执行 - 请求ID: {request_info.get('request_id', 'N/A')}");
        }}
        </script>
        '''
        
        head_end = html_content.lower().find('</head>')
        if head_end != -1:
            return html_content[:head_end] + xss_script + html_content[head_end:]
        else:
            body_end = html_content.lower().find('</body>')
            if body_end != -1:
                return html_content[:body_end] + xss_script + html_content[body_end:]
        
        return html_content + xss_script
    
    def _beacon_injection(self, html_content: str, request_info: Dict, config: Dict) -> str:
        """信标注入 - 用于监控"""
        beacon_url = config.get('beacon_url', f'http://127.0.0.1:8080/beacon')
        
        beacon_script = f'''
        <script>
        // 页面访问信标
        window.addEventListener('load', function() {{
            var img = new Image();
            img.src = '{beacon_url}?id={request_info.get("request_id", "N/A")}&url=' + 
                      encodeURIComponent(window.location.href) + 
                      '&time=' + Date.now();
        }});
        </script>
        '''
        
        head_end = html_content.lower().find('</head>')
        if head_end != -1:
            return html_content[:head_end] + beacon_script + html_content[head_end:]
        
        return html_content

class RequestManager:
    """
    请求管理器 - 使用requests库处理HTTP请求
    """
    
    def __init__(self):
        self.sessions: Dict[str, requests.Session] = {}
        self.session_lock = threading.Lock()
        self.request_timeout = (3, 10)  # 连接超时3秒，读取超时10秒
        
        # 初始化默认session
        self._init_default_session()
    
    def _init_default_session(self):
        """初始化默认session"""
        session = requests.Session()
        
        # 关键配置：绕过系统代理
        session.trust_env = False
        session.proxies.clear()
        
        # 配置重试策略
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # 设置通用headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
        })
        
        self.sessions['default'] = session
    
    def get_session(self, domain: str = 'default') -> requests.Session:
        """获取指定域的session"""
        with self.session_lock:
            if domain not in self.sessions:
                # 创建新的session（可以针对特定域进行优化）
                self.sessions[domain] = self._create_domain_session(domain)
            return self.sessions[domain]
    
    def _create_domain_session(self, domain: str) -> requests.Session:
        """创建针对特定域的session"""
        session = requests.Session()
        session.trust_env = False
        session.proxies.clear()
        
        # 可以在这里为特定域设置特殊配置
        if 'google' in domain:
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
        
        return session
    
    def make_request(self, url: str, headers: Dict, method: str = 'GET', data: Any = None) -> requests.Response:
        """发送HTTP请求"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        session = self.get_session(domain)
        
        # 准备请求头
        request_headers = self._prepare_headers(headers)
        
        try:
            response = session.request(
                method=method.upper(),
                url=url,
                headers=request_headers,
                data=data,
                timeout=self.request_timeout,
                verify=False,  # 忽略SSL验证
                allow_redirects=True
            )
            
            logger.debug(f"请求成功: {url} - 状态: {response.status_code}")
            return response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"请求失败: {url} - 错误: {e}")
            raise
    
    def _prepare_headers(self, original_headers: Dict) -> Dict:
        """准备请求头，过滤不必要的头"""
        exclude_headers = {
            'host', 'content-length', 'connection', 'proxy-connection',
            'upgrade', 'accept-encoding', 'cookie', 'cache-control'
        }
        
        headers = {}
        for key, value in original_headers.items():
            if key.lower() not in exclude_headers:
                headers[key] = value
        
        return headers
    
    def close_all_sessions(self):
        """关闭所有session"""
        with self.session_lock:
            for name, session in self.sessions.items():
                try:
                    session.close()
                    logger.debug(f"关闭session: {name}")
                except Exception as e:
                    logger.error(f"关闭session失败 {name}: {e}")
            self.sessions.clear()

class ConnectionTracker:
    """
    连接跟踪器 - 监控和管理活跃连接
    """
    
    def __init__(self):
        self.active_connections: Dict[str, Dict] = {}
        self.connection_lock = threading.Lock()
        self.connection_timeout = 300  # 5分钟超时
    
    def add_connection(self, connection_id: str, info: Dict):
        """添加新连接"""
        with self.connection_lock:
            info['start_time'] = time.time()
            info['last_activity'] = time.time()
            self.active_connections[connection_id] = info
            logger.debug(f"添加连接: {connection_id}")
    
    def update_activity(self, connection_id: str):
        """更新连接活动时间"""
        with self.connection_lock:
            if connection_id in self.active_connections:
                self.active_connections[connection_id]['last_activity'] = time.time()
    
    def remove_connection(self, connection_id: str):
        """移除连接"""
        with self.connection_lock:
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]
                logger.debug(f"移除连接: {connection_id}")
    
    def cleanup_stale_connections(self):
        """清理超时连接"""
        with self.connection_lock:
            current_time = time.time()
            stale_connections = []
            
            for conn_id, info in self.active_connections.items():
                if current_time - info['last_activity'] > self.connection_timeout:
                    stale_connections.append(conn_id)
            
            for conn_id in stale_connections:
                del self.active_connections[conn_id]
                logger.info(f"清理超时连接: {conn_id}")
            
            return len(stale_connections)
    
    def get_connection_stats(self) -> Dict:
        """获取连接统计"""
        with self.connection_lock:
            return {
                'total_connections': len(self.active_connections),
                'connections': list(self.active_connections.keys())
            }

class WinEdgeProxyHandler(BaseHTTPRequestHandler):
    """
    Windows Edge浏览器代理处理器
    """
    
    protocol_version = 'HTTP/1.1'
    
    # 类属性 - 所有实例共享
    request_manager: Optional[RequestManager] = None
    injection_engine: Optional[InjectionEngine] = None
    connection_tracker: Optional[ConnectionTracker] = None
    
    # 请求计数器
    _request_counter = 0
    _counter_lock = threading.Lock()
    
    def __init__(self, *args, **kwargs):
        # 生成请求ID
        with self._counter_lock:
            WinEdgeProxyHandler._request_counter += 1
            self.request_id = f"REQ-{WinEdgeProxyHandler._request_counter:06d}"
        
        self.request_start_time = time.time()
        self.connection_id = f"CONN-{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        
        super().__init__(*args, **kwargs)
    
    def setup(self):
        """设置连接跟踪"""
        super().setup()
        if self.connection_tracker:
            self.connection_tracker.add_connection(self.connection_id, {
                'client_address': self.client_address,
                'start_time': time.time()
            })
    
    def handle(self):
        """处理请求 - 重写以添加活动更新"""
        if self.connection_tracker:
            self.connection_tracker.update_activity(self.connection_id)
        super().handle()
    
    def finish(self):
        """完成请求处理"""
        if self.connection_tracker:
            self.connection_tracker.remove_connection(self.connection_id)
        super().finish()
    
    def _build_target_url(self) -> str:
        """构建目标URL"""
        if self.path.startswith(('http://', 'https://')):
            return self.path
        
        host_header = self.headers.get('Host', '')
        if host_header:
            scheme = 'https' if self.headers.get('X-Forwarded-Proto') == 'https' else 'http'
            return f"{scheme}://{host_header}{self.path}"
        else:
            return f"http://httpbin.org{self.path}"  # 默认回退
    
    def _handle_special_paths(self) -> bool:
        """处理特殊路径"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/':
            content = self._generate_status_page()
            self._send_response(200, 'text/html; charset=utf-8', content)
            return True
            
        elif path == '/favicon.ico':
            self._send_response(204, 'text/plain', b'')  # No Content
            return True
            
        elif path == '/status':
            stats = self._get_system_status()
            content = json.dumps(stats, indent=2, ensure_ascii=False)
            self._send_response(200, 'application/json', content.encode('utf-8'))
            return True
            
        elif path == '/proxy-config':
            config = self._get_proxy_config()
            content = json.dumps(config, indent=2, ensure_ascii=False)
            self._send_response(200, 'application/json', content.encode('utf-8'))
            return True
            
        elif path == '/network-test':
            content = self._test_network_connection()
            self._send_response(200, 'text/html; charset=utf-8', content)
            return True
            
        elif path == '/beacon':
            # 信标端点
            logger.info(f"信标请求: {self.request_id} - 查询: {parsed_path.query}")
            self._send_response(204, 'text/plain', b'')
            return True
            
        return False
    
    def _generate_status_page(self) -> bytes:
        """生成状态页面"""
        stats = self._get_system_status()
        
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Windows Edge 代理服务器</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .status {{ padding: 20px; margin: 10px 0; border-radius: 5px; }}
                .running {{ background: #d4edda; border: 1px solid #c3e6cb; }}
                .info {{ background: #d1ecf1; border: 1px solid #bee5eb; }}
                .test-links {{ margin: 20px 0; }}
                .test-links a {{ display: block; margin: 5px 0; padding: 10px; background: #007bff; color: white; text-decoration: none; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <h1>🚀 Windows Edge 代理服务器</h1>
            
            <div class="status running">
                <h2>✅ 服务器运行正常</h2>
                <p>请求ID: {self.request_id}</p>
                <p>总请求数: {stats['total_requests']}</p>
                <p>活跃连接: {stats['active_connections']}</p>
                <p>运行时间: {stats['uptime']}秒</p>
            </div>
            
            <div class="status info">
                <h3>🔧 配置信息</h3>
                <p>启用注入: {', '.join(stats['enabled_injections'])}</p>
                <p>会话数量: {stats['session_count']}</p>
            </div>
            
            <div class="test-links">
                <h3>🧪 测试链接</h3>
                <a href="/network-test">网络连接测试</a>
                <a href="http://httpbin.org/html" target="_blank">测试 HTTPBin HTML</a>
                <a href="http://example.com" target="_blank">测试 Example.com</a>
                <a href="/status" target="_blank">JSON状态接口</a>
            </div>
            
            <div class="status info">
                <h3>📝 使用说明</h3>
                <p>1. 在Windows设置中配置系统代理: 127.0.0.1:8080</p>
                <p>2. 使用Edge浏览器访问任意HTTP网站</p>
                <p>3. 查看页面左上角的红色横幅确认注入成功</p>
            </div>
        </body>
        </html>
        '''
        
        return html.encode('utf-8')
    
    def _get_system_status(self) -> Dict:
        """获取系统状态"""
        connection_stats = self.connection_tracker.get_connection_stats() if self.connection_tracker else {}
        
        return {
            'status': 'running',
            'request_id': self.request_id,
            'total_requests': WinEdgeProxyHandler._request_counter,
            'active_connections': connection_stats.get('total_connections', 0),
            'enabled_injections': self.injection_engine.enabled_injections if self.injection_engine else [],
            'session_count': len(self.request_manager.sessions) if self.request_manager else 0,
            'uptime': int(time.time() - self.request_start_time),
            'timestamp': time.time()
        }
    
    def _get_proxy_config(self) -> Dict:
        """获取代理配置"""
        return {
            'injection_engine': {
                'available_injections': list(self.injection_engine.injections.keys()) if self.injection_engine else [],
                'enabled_injections': self.injection_engine.enabled_injections if self.injection_engine else []
            },
            'request_manager': {
                'session_count': len(self.request_manager.sessions) if self.request_manager else 0,
                'timeout': self.request_manager.request_timeout if self.request_manager else None
            }
        }
    
    def _test_network_connection(self) -> bytes:
        """网络连接测试"""
        test_sites = [
            'http://httpbin.org/html',
            'http://example.com',
            'http://www.baidu.com',
            'http://www.qq.com'
        ]
        
        results = []
        for site in test_sites:
            try:
                start_time = time.time()
                response = self.request_manager.make_request(site, {}, 'GET')
                end_time = time.time()
                
                status = '✅' if response.status_code == 200 else '⚠️'
                results.append(f"{status} {site}: {response.status_code} ({(end_time-start_time)*1000:.0f}ms)")
                response.close()
                
            except Exception as e:
                results.append(f"❌ {site}: {e}")
        
        html = f"""
        <h1>网络连接测试</h1>
        <ul>
            {"".join(f"<li>{r}</li>" for r in results)}
        </ul>
        <p><a href="/">返回首页</a></p>
        """
        
        return html.encode('utf-8')
    
    def _send_response(self, status_code: int, content_type: str, content: bytes, headers: Dict = None):
        """发送HTTP响应"""
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
            
            logger.info(f"响应发送: {status_code} - 长度: {len(content)}")
            
        except Exception as e:
            logger.error(f"发送响应失败: {e}")
        finally:
            self.close_connection = True
    
    def _handle_proxy_request(self, method: str):
        """处理代理请求"""
        logger.info(f"开始处理 {method} {self.path} - ID: {self.request_id}")
        
        # 处理特殊路径
        if self._handle_special_paths():
            return
        
        try:
            # 构建目标URL
            target_url = self._build_target_url()
            logger.debug(f"目标URL: {target_url}")
            
            # 准备请求头
            headers = dict(self.headers)
            
            # 处理请求体
            post_data = None
            if method in ['POST', 'PUT', 'PATCH']:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    post_data = self.rfile.read(content_length)
            
            # 发送请求
            response = self.request_manager.make_request(target_url, headers, method, post_data)
            
            # 获取响应内容
            content = response.content
            content_type = response.headers.get('Content-Type', 'text/plain')
            
            # 准备注入信息
            request_info = {
                'request_id': self.request_id,
                'url': target_url,
                'method': method,
                'client_ip': self.client_address[0],
                'user_agent': headers.get('User-Agent', '')
            }
            
            # 执行注入
            if self.injection_engine and self.injection_engine.enabled_injections:
                content = self.injection_engine.inject(content, content_type, request_info)
            
            # 准备响应头
            response_headers = {}
            for key, value in response.headers.items():
                if key.lower() not in ['content-length', 'transfer-encoding', 'connection']:
                    response_headers[key] = value
            
            # 发送响应
            self._send_response(response.status_code, content_type, content, response_headers)
            
            total_time = time.time() - self.request_start_time
            logger.info(f"请求完成: {self.request_id} - 状态: {response.status_code} - 耗时: {total_time:.2f}s")
            
        except Exception as e:
            logger.error(f"处理请求失败: {self.request_id} - 错误: {e}")
            error_content = f"代理请求失败: {str(e)}".encode('utf-8')
            self._send_response(502, 'text/plain; charset=utf-8', error_content)
    
    def do_GET(self):
        self._handle_proxy_request('GET')
    
    def do_POST(self):
        self._handle_proxy_request('POST')
    
    def do_PUT(self):
        self._handle_proxy_request('PUT')
    
    def do_DELETE(self):
        self._handle_proxy_request('DELETE')
    
    def do_HEAD(self):
        self._handle_proxy_request('HEAD')
    
    def do_OPTIONS(self):
        self._handle_proxy_request('OPTIONS')
    
    def do_CONNECT(self):
        """处理CONNECT请求 - 简化HTTPS支持"""
        logger.warning(f"HTTPS请求被拒绝: {self.request_id}")
        self._send_response(501, 'text/plain', b'HTTPS not supported in this version')
    
    def log_message(self, format, *args):
        """禁用默认日志，使用自定义logger"""
        pass

class WinEdgeProxyServer:
    """
    Windows Edge代理服务器 - 强化资源管理
    """
    
    def __init__(self, port: int = 8080, host: str = '127.0.0.1'):
        self.port = port
        self.host = host
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.shutdown_event = threading.Event()
        self.cleanup_lock = threading.Lock()
        
        # 初始化组件
        self.request_manager = RequestManager()
        self.injection_engine = InjectionEngine()
        self.connection_tracker = ConnectionTracker()
        
        # 设置类属性
        WinEdgeProxyHandler.request_manager = self.request_manager
        WinEdgeProxyHandler.injection_engine = self.injection_engine
        WinEdgeProxyHandler.connection_tracker = self.connection_tracker
        
        # 清理线程
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        
        # 配置默认注入
        self._setup_default_injections()
    
    def _setup_default_injections(self):
        """设置默认注入"""
        self.injection_engine.enable_injection('html_banner', {
            'text': '🚀 Windows Edge 代理注入成功！',
            'style': 'position:fixed; top:10px; left:10px; background:linear-gradient(45deg, #ff6b6b, #4ecdc4); color:white; padding:12px 20px; border-radius:8px; border:2px solid #ffd93d; z-index:9999; font-size:16px; font-weight:bold; box-shadow:0 4px 12px rgba(0,0,0,0.3);'
        })
    
    def _cleanup_ports(self):
        """清理端口占用"""
        try:
            logger.info(f"清理端口 {self.port}...")
            
            if os.name == 'nt':  # Windows
                # 使用netstat查找占用端口的进程
                cmd = f'netstat -ano | findstr :{self.port}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    pids = set()
                    
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 5:
                            pid = parts[-1]
                            pids.add(pid)
                    
                    # 终止进程
                    for pid in pids:
                        try:
                            subprocess.run(f'taskkill /F /PID {pid}', shell=True, 
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            logger.info(f"终止进程: PID {pid}")
                        except:
                            pass
                
                time.sleep(2)
                
            else:  # Linux/Mac
                subprocess.run(f'fuser -k {self.port}/tcp 2>/dev/null', shell=True)
                time.sleep(1)
                
        except Exception as e:
            logger.warning(f"清理端口时出错: {e}")
    
    def _cleanup_worker(self):
        """清理工作线程"""
        while not self.shutdown_event.is_set():
            try:
                # 每30秒清理一次超时连接
                time.sleep(30)
                if self.connection_tracker:
                    cleaned = self.connection_tracker.cleanup_stale_connections()
                    if cleaned > 0:
                        logger.info(f"清理了 {cleaned} 个超时连接")
                
                # 清理请求管理器的空闲session
                if self.request_manager:
                    # 这里可以添加session清理逻辑
                    pass
                    
            except Exception as e:
                logger.error(f"清理工作线程出错: {e}")
    
    def _signal_handler(self, signum, frame):
        """信号处理"""
        logger.info(f"收到停止信号 {signum}")
        self.stop()
    
    def _force_shutdown(self):
        """强制关闭"""
        logger.warning("执行强制关闭...")
        try:
            if self.httpd:
                self.httpd.shutdown()
                self.httpd.server_close()
        except:
            pass
        
        # 强制清理
        self._cleanup_all_resources()
        os._exit(1)
    
    def _cleanup_all_resources(self):
        """清理所有资源"""
        with self.cleanup_lock:
            logger.info("开始清理所有资源...")
            
            # 关闭请求管理器
            if self.request_manager:
                self.request_manager.close_all_sessions()
            
            # 关闭HTTP服务器
            if self.httpd:
                try:
                    self.httpd.shutdown()
                    self.httpd.server_close()
                    logger.info("HTTP服务器已关闭")
                except Exception as e:
                    logger.error(f"关闭HTTP服务器失败: {e}")
                finally:
                    self.httpd = None
            
            logger.info("资源清理完成")
    
    def start(self):
        """启动代理服务器"""
        try:
            # 清理可能占用的端口
            self._cleanup_ports()
            
            # 注册信号处理
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            # 创建服务器
            server_address = (self.host, self.port)
            self.httpd = ThreadingHTTPServer(server_address, WinEdgeProxyHandler)
            
            # 配置socket
            self.httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.httpd.timeout = 0.5  # 短超时以便检查关闭事件
            
            # 启动清理线程
            self.cleanup_thread.start()
            
            logger.info(f"🚀 Windows Edge 代理服务器启动在 {self.host}:{self.port}")
            logger.info("📋 使用说明:")
            logger.info("  1. Windows设置 → 网络和Internet → 代理")
            logger.info("  2. 启用'使用代理服务器'")
            logger.info(f"  3. 地址: {self.host}, 端口: {self.port}")
            logger.info("  4. 保存设置，用Edge访问 http://httpbin.org/html 测试")
            logger.info("  5. 访问 http://127.0.0.1:8080 查看服务器状态")
            logger.info("⏹️  Ctrl+C 停止服务器")
            logger.info("-" * 60)
            
            # 主服务循环
            while not self.shutdown_event.is_set():
                try:
                    self.httpd.handle_request()
                except socket.timeout:
                    continue  # 正常超时，继续循环
                except Exception as e:
                    if not self.shutdown_event.is_set():
                        logger.error(f"处理请求时出错: {e}")
            
            logger.info("服务器主循环结束")
            
        except Exception as e:
            logger.error(f"启动服务器失败: {e}")
            raise
        finally:
            self._cleanup_all_resources()
    
    def stop(self):
        """停止服务器"""
        logger.info("正在停止服务器...")
        self.shutdown_event.set()
        
        # 设置强制关闭超时
        def force_exit():
            time.sleep(5)
            logger.error("正常关闭超时，执行强制关闭")
            self._force_shutdown()
        
        force_thread = threading.Thread(target=force_exit, daemon=True)
        force_thread.start()
        
        self._cleanup_all_resources()
        logger.info("服务器已停止")

def main():
    """主函数"""
    print("=" * 60)
    print("🖥️  Windows Edge 代理服务器")
    print("=" * 60)
    
    try:
        # 创建代理服务器
        proxy = WinEdgeProxyServer(port=8080)
        
        # 启动服务器
        proxy.start()
        
    except KeyboardInterrupt:
        print("\n用户中断")
    except Exception as e:
        print(f"服务器异常: {e}")
        logging.error(f"服务器异常: {e}", exc_info=True)
    finally:
        print("程序退出")

if __name__ == '__main__':
    main()