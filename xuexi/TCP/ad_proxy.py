#  广告插入

import http.server
import socketserver
import threading
import time
import json
import hashlib
from urllib.parse import urlparse, parse_qs
import requests
from urllib3.exceptions import InsecureRequestWarning

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class AdManager:
    """广告管理器 - 支持多种广告类型"""
    
    def __init__(self):
        self.ads = {
            'banner': {
                'name': '横幅广告',
                'html': '''
                <div style="position: fixed; top: 0; left: 0; width: 100%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; text-align: center; z-index: 9999; box-shadow: 0 2px 10px rgba(0,0,0,0.3);">
                    <strong>🚀 特价优惠！</strong> 限时折扣，立即购买享受 50% 优惠！
                    <a href="/ad-click?type=banner" style="color: #ffeb3b; margin-left: 20px; text-decoration: underline;">点击了解</a>
                    <button onclick="this.parentElement.style.display='none'" style="background: transparent; border: 1px solid white; color: white; margin-left: 20px; cursor: pointer;">×</button>
                </div>
                '''
            },
            'sidebar': {
                'name': '侧边栏广告',
                'html': '''
                <div style="position: fixed; right: 20px; top: 50%; transform: translateY(-50%); width: 160px; background: white; border: 2px solid #4CAF50; border-radius: 10px; padding: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 9998;">
                    <img src="https://via.placeholder.com/160x100/4CAF50/white?text=广告" style="width: 100%; border-radius: 5px;">
                    <h4 style="margin: 10px 0 5px; color: #333;">新品上市</h4>
                    <p style="font-size: 12px; color: #666;">立即体验最新产品</p>
                    <a href="/ad-click?type=sidebar" style="display: block; background: #4CAF50; color: white; text-align: center; padding: 8px; border-radius: 5px; text-decoration: none; margin-top: 10px;">查看详情</a>
                </div>
                '''
            },
            'video': {
                'name': '视频广告占位',
                'html': '''
                <div style="position: fixed; bottom: 20px; left: 20px; width: 300px; background: #000; border-radius: 10px; padding: 10px; z-index: 9997;">
                    <div style="background: #333; height: 180px; display: flex; align-items: center; justify-content: center; border-radius: 5px;">
                        <div style="text-align: center; color: white;">
                            <div style="font-size: 48px;">▶️</div>
                            <div>视频广告</div>
                        </div>
                    </div>
                    <div style="color: white; padding: 10px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                            <span>广告</span>
                            <button onclick="this.parentElement.parentElement.style.display='none'" style="background: transparent; border: none; color: white; cursor: pointer;">跳过广告</button>
                        </div>
                        <div style="background: #444; height: 4px; border-radius: 2px; overflow: hidden;">
                            <div style="background: #ff5722; width: 30%; height: 100%;"></div>
                        </div>
                    </div>
                </div>
                '''
            },
            'popup': {
                'name': '弹窗广告',
                'html': '''
                <div id="ad-popup" style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 300px; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); z-index: 10000; padding: 20px;">
                    <div style="text-align: center;">
                        <div style="font-size: 48px; color: #ff6b6b;">🎉</div>
                        <h3 style="margin: 10px 0; color: #333;">特别优惠！</h3>
                        <p style="color: #666; margin-bottom: 20px;">注册即可获得 100元 优惠券</p>
                        <div style="display: flex; gap: 10px;">
                            <button onclick="document.getElementById('ad-popup').style.display='none'" style="flex: 1; padding: 10px; border: 1px solid #ddd; background: white; border-radius: 5px; cursor: pointer;">稍后</button>
                            <a href="/ad-click?type=popup" style="flex: 1; padding: 10px; background: #ff6b6b; color: white; text-align: center; border-radius: 5px; text-decoration: none;">立即领取</a>
                        </div>
                    </div>
                </div>
                <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 9999;"></div>
                '''
            }
        }
        
        self.enabled_ads = ['banner']  # 默认启用的广告
        self.ad_clicks = {}  # 广告点击统计
    
    def enable_ad(self, ad_type):
        """启用指定类型的广告"""
        if ad_type in self.ads and ad_type not in self.enabled_ads:
            self.enabled_ads.append(ad_type)
            return True
        return False
    
    def disable_ad(self, ad_type):
        """禁用指定类型的广告"""
        if ad_type in self.enabled_ads:
            self.enabled_ads.remove(ad_type)
            return True
        return False
    
    def record_ad_click(self, ad_type):
        """记录广告点击"""
        if ad_type not in self.ad_clicks:
            self.ad_clicks[ad_type] = 0
        self.ad_clicks[ad_type] += 1
    
    def get_all_ads(self):
        """获取所有广告信息"""
        return self.ads
    
    def get_enabled_ads_html(self):
        """获取所有启用的广告HTML"""
        html_parts = []
        for ad_type in self.enabled_ads:
            if ad_type in self.ads:
                html_parts.append(self.ads[ad_type]['html'])
        return '\n'.join(html_parts)

class AdProxyHandler(http.server.SimpleHTTPRequestHandler):
    """广告代理处理器"""
    
    ad_manager = AdManager()
    request_count = 0
    blocked_paths = ['/favicon.ico', '/ads/', '/adserver/']  # 阻止某些路径避免循环
    
    def do_GET(self):
        """处理GET请求"""
        # 检查是否应该阻止此路径
        if any(self.path.startswith(blocked) for blocked in self.blocked_paths):
            self.send_error(404, "Blocked path")
            return
            
        self.request_count += 1
        request_id = f"REQ-{self.request_count:06d}"
        
        print(f"[{request_id}] 请求: {self.path}")
        
        # 处理特殊路径
        if self._handle_special_paths():
            return
        
        # 代理请求到目标网站
        self._proxy_request(request_id)
    
    def _handle_special_paths(self):
        """处理特殊路径"""
        if self.path == '/':
            self._send_status_page()
            return True
        elif self.path == '/control':
            self._send_control_panel()
            return True
        elif self.path == '/stats':
            self._send_stats_page()
            return True
        elif self.path.startswith('/ad-click'):
            self._handle_ad_click()
            return True
        elif self.path.startswith('/api/'):
            self._handle_api_request()
            return True
        return False
    
    def _handle_api_request(self):
        """处理API请求"""
        if self.path == '/api/ads':
            # 获取广告配置
            ads_info = {
                'all_ads': self.ad_manager.get_all_ads(),
                'enabled_ads': self.ad_manager.enabled_ads,
                'stats': self.ad_manager.ad_clicks
            }
            self._send_json_response(ads_info)
            
        elif self.path.startswith('/api/enable-ad/'):
            # 启用广告
            ad_type = self.path.split('/')[-1]
            success = self.ad_manager.enable_ad(ad_type)
            self._send_json_response({'success': success, 'ad_type': ad_type})
            
        elif self.path.startswith('/api/disable-ad/'):
            # 禁用广告
            ad_type = self.path.split('/')[-1]
            success = self.ad_manager.disable_ad(ad_type)
            self._send_json_response({'success': success, 'ad_type': ad_type})
        
        else:
            self._send_json_response({'error': 'API not found'}, 404)
    
    def _handle_ad_click(self):
        """处理广告点击"""
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)
        ad_type = query_params.get('type', ['unknown'])[0]
        
        print(f"广告点击: {ad_type}")
        self.ad_manager.record_ad_click(ad_type)
        
        # 在实际应用中，这里可以记录点击数据、跳转到真实广告链接等
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>广告点击 - {ad_type}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; text-align: center; }}
                .success {{ color: #4CAF50; font-size: 24px; }}
                .info {{ background: #f5f5f5; padding: 20px; border-radius: 10px; margin: 20px auto; max-width: 500px; }}
            </style>
        </head>
        <body>
            <div class="success">✅ 广告点击已记录</div>
            <div class="info">
                <h3>广告类型: {ad_type}</h3>
                <p>总点击次数: {self.ad_manager.ad_clicks.get(ad_type, 0)}</p>
                <p>这是一个演示页面。在实际应用中，这里会跳转到真实的广告链接。</p>
                <p><a href="/control">返回控制面板</a> | <a href="/stats">查看统计</a> | <a href="/">返回主页</a></p>
            </div>
        </body>
        </html>
        '''
        
        self._send_html_response(html)
    
    def _send_status_page(self):
        """发送状态页面"""
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>广告代理服务器</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 30px; border-radius: 10px; }}
                .card {{ background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .btn {{ background: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; }}
                .test-sites {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
                .test-site {{ background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #4CAF50; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚀 广告代理服务器</h1>
                <p>实时广告插入测试平台</p>
            </div>
            
            <div class="card">
                <h2>📊 服务器状态</h2>
                <p><strong>请求计数:</strong> {self.request_count}</p>
                <p><strong>运行时间:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>启用的广告:</strong> {', '.join(self.ad_manager.enabled_ads)}</p>
            </div>
            
            <div class="card">
                <h2>🎯 快速开始</h2>
                <ol>
                    <li>点击下方"控制面板"配置广告类型</li>
                    <li>访问测试网站查看广告效果</li>
                    <li>实时调整广告设置</li>
                </ol>
                <a href="/control" class="btn">进入控制面板</a>
                <a href="/stats" class="btn" style="background: #2196F3;">查看统计</a>
            </div>
            
            <div class="card">
                <h2>🌐 测试网站</h2>
                <p>通过代理访问这些网站查看广告效果：</p>
                <div class="test-sites">
                    <div class="test-site">
                        <h4>HTTPBin</h4>
                        <p><a href="/proxy/http://httpbin.org/html" target="_blank">http://httpbin.org/html</a></p>
                    </div>
                    <div class="test-site">
                        <h4>Example</h4>
                        <p><a href="/proxy/http://example.com" target="_blank">http://example.com</a></p>
                    </div>
                    <div class="test-site">
                        <h4>测试页面</h4>
                        <p><a href="/proxy/http://httpbin.org/forms/post" target="_blank">表单测试页</a></p>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>📖 使用说明</h2>
                <p><strong>方式1 - 直接访问:</strong> 点击上方测试链接</p>
                <p><strong>方式2 - 配置代理:</strong></p>
                <ul>
                    <li>Chrome: 设置 → 高级 → 系统 → 打开代理设置</li>
                    <li>Windows: 设置 → 网络和Internet → 代理</li>
                    <li>配置: 地址: 127.0.0.1, 端口: 8080</li>
                </ul>
            </div>
        </body>
        </html>
        '''
        
        self._send_html_response(html)
    
    def _send_stats_page(self):
        """发送统计页面"""
        stats_html = ""
        for ad_type, count in self.ad_manager.ad_clicks.items():
            stats_html += f'''
            <div class="stat-item">
                <h3>{ad_type}</h3>
                <div class="count">{count} 次点击</div>
            </div>
            '''
        
        if not stats_html:
            stats_html = '<p>暂无点击数据</p>'
            
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>广告统计</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 800px; margin: 0 auto; }}
                .header {{ background: linear-gradient(135deg, #2196F3, #21CBF3); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
                .stat-item {{ background: white; padding: 20px; margin: 15px 0; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .count {{ font-size: 24px; color: #2196F3; font-weight: bold; }}
                .nav {{ margin: 20px 0; }}
                .nav a {{ color: #2196F3; text-decoration: none; margin-right: 15px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📈 广告点击统计</h1>
                    <p>实时监控广告效果</p>
                </div>
                
                <div class="nav">
                    <a href="/">← 返回主页</a>
                    <a href="/control">控制面板</a>
                </div>
                
                <div class="card">
                    <h2>广告点击数据</h2>
                    {stats_html}
                </div>
            </div>
        </body>
        </html>
        '''
        
        self._send_html_response(html)
    
    def _send_control_panel(self):
        """发送控制面板"""
        all_ads = self.ad_manager.get_all_ads()
        enabled_ads = self.ad_manager.enabled_ads
        
        ads_html = ''
        for ad_type, ad_info in all_ads.items():
            is_enabled = ad_type in enabled_ads
            status_color = '#4CAF50' if is_enabled else '#f44336'
            status_text = '启用' if is_enabled else '禁用'
            button_text = '禁用' if is_enabled else '启用'
            action = 'disable' if is_enabled else 'enable'
            
            ads_html += f'''
            <div class="ad-item" style="border-left: 4px solid {status_color};">
                <h3>{ad_info['name']} <span style="color: {status_color};">({status_text})</span></h3>
                <p>类型: <code>{ad_type}</code></p>
                <button onclick="toggleAd('{ad_type}', '{action}')" class="btn {'btn-disable' if is_enabled else 'btn-enable'}">
                    {button_text}
                </button>
                <div class="ad-preview">
                    {ad_info['html']}
                </div>
            </div>
            '''
        
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>广告控制面板</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1000px; margin: 0 auto; }}
                .header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
                .ad-item {{ background: white; padding: 20px; margin: 15px 0; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .btn {{ padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }}
                .btn-enable {{ background: #4CAF50; color: white; }}
                .btn-disable {{ background: #f44336; color: white; }}
                .ad-preview {{ margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 5px; position: relative; }}
                .nav {{ margin: 20px 0; }}
                .nav a {{ color: #667eea; text-decoration: none; margin-right: 15px; }}
                .test-links {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 20px 0; }}
                .test-link {{ background: #e3f2fd; padding: 10px; border-radius: 5px; text-align: center; }}
            </style>
            <script>
                async function toggleAd(adType, action) {{
                    const response = await fetch(`/api/${{action}}-ad/${{adType}}`);
                    const result = await response.json();
                    
                    if (result.success) {{
                        alert(`广告 ${{adType}} ${{action === 'enable' ? '已启用' : '已禁用'}}`);
                        location.reload();
                    }} else {{
                        alert('操作失败');
                    }}
                }}
            </script>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎛️ 广告控制面板</h1>
                    <p>实时管理广告插入设置</p>
                </div>
                
                <div class="nav">
                    <a href="/">← 返回主页</a>
                    <a href="/stats">查看统计</a>
                </div>
                
                <div class="test-links">
                    <div class="test-link">
                        <a href="/proxy/http://httpbin.org/html" target="_blank">测试 HTTPBin</a>
                    </div>
                    <div class="test-link">
                        <a href="/proxy/http://example.com" target="_blank">测试 Example.com</a>
                    </div>
                    <div class="test-link">
                        <a href="/proxy/http://httpbin.org/forms/post" target="_blank">测试表单页面</a>
                    </div>
                </div>
                
                <div class="card">
                    <h2>📢 广告管理</h2>
                    <p>启用或禁用不同类型的广告，然后点击上方测试链接查看效果。</p>
                    
                    {ads_html}
                </div>
            </div>
        </body>
        </html>
        '''
        
        self._send_html_response(html)
    
    def _build_target_url(self, path):
        """构建目标URL"""
        # 处理代理路径
        if path.startswith('/proxy/'):
            return path[7:]  # 去掉 '/proxy/' 前缀
        
        # 从Host头获取目标主机
        host = self.headers.get('Host', '')
        if host and not host.startswith('127.0.0.1') and not host.startswith('localhost'):
            return f'http://{host}{path}'
        
        return None
    
    def _proxy_request(self, request_id):
        """代理请求到目标网站并插入广告"""
        try:
            # 构建目标URL
            target_url = self._build_target_url(self.path)
            
            if not target_url:
                self._send_error_page(400, "无法确定目标URL")
                return
            
            print(f"[{request_id}] 代理到: {target_url}")
            
            # 使用requests发送请求，禁用代理避免循环
            session = requests.Session()
            session.trust_env = False  # 不读取系统代理设置
            
            # 复制请求头
            headers = {}
            for key, value in self.headers.items():
                if key.lower() not in ['host', 'connection', 'accept-encoding', 'proxy-connection']:
                    headers[key] = value
            
            # 发送请求
            response = session.get(
                target_url, 
                headers=headers,
                timeout=30,
                verify=False  # 忽略SSL证书验证
            )
            
            content = response.content
            content_type = response.headers.get('Content-Type', '')
            
            # 如果是HTML内容，插入广告
            if 'text/html' in content_type:
                html_content = content.decode('utf-8', errors='ignore')
                
                # 插入广告代码
                ads_html = self.ad_manager.get_enabled_ads_html()
                if ads_html:
                    # 在</body>标签前插入广告
                    body_end = html_content.lower().rfind('</body>')
                    if body_end != -1:
                        html_content = html_content[:body_end] + ads_html + html_content[body_end:]
                    else:
                        # 如果没有body标签，直接添加到末尾
                        html_content += ads_html
                    
                    content = html_content.encode('utf-8')
                    print(f"[{request_id}] 广告插入完成")
            
            # 发送响应
            self.send_response(response.status_code)
            
            # 复制响应头
            for key, value in response.headers.items():
                key_lower = key.lower()
                if key_lower not in ['content-length', 'transfer-encoding', 'content-encoding', 'connection']:
                    self.send_header(key, value)
            
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            
            print(f"[{request_id}] 响应完成: {response.status_code}")
            
        except Exception as e:
            print(f"[{request_id}] 代理错误: {e}")
            self._send_error_page(502, f"代理错误: {str(e)}")
    
    def _send_error_page(self, code, message):
        """发送错误页面"""
        error_html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>错误 {code}</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; text-align: center; }}
                .error {{ color: #f44336; font-size: 24px; }}
                .info {{ background: #f5f5f5; padding: 20px; border-radius: 10px; margin: 20px auto; max-width: 500px; }}
            </style>
        </head>
        <body>
            <div class="error">❌ 错误 {code}</div>
            <div class="info">
                <h3>{message}</h3>
                <p><a href="/">返回主页</a> | <a href="/control">控制面板</a></p>
            </div>
        </body>
        </html>
        '''
        
        self._send_html_response(error_html, code)
    
    def _send_html_response(self, html_content, status=200):
        """发送HTML响应"""
        content = html_content.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)
    
    def _send_json_response(self, data, status=200):
        """发送JSON响应"""
        content = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

def run_proxy_server(port=8080):
    """运行代理服务器"""
    with socketserver.ThreadingTCPServer(("", port), AdProxyHandler) as httpd:
        print("=" * 60)
        print("🚀 广告代理服务器启动成功!")
        print("=" * 60)
        print(f"📡 本地地址: http://127.0.0.1:{port}")
        print("🌐 控制面板: http://127.0.0.1:8080/control")
        print("📊 统计页面: http://127.0.0.1:8080/stats")
        print("📖 使用方式:")
        print("  方式1: 直接访问控制面板中的测试链接")
        print("  方式2: 配置浏览器代理 → 127.0.0.1:8080")
        print("=" * 60)
        print("💡 提示: 使用 requests 库，避免系统代理问题")
        print("=" * 60)
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n⏹️  服务器已停止")

if __name__ == "__main__":
    run_proxy_server()