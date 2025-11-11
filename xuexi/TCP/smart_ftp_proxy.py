import socket
import threading
import re
import struct
import sys
import os
import time
import select
from typing import Tuple, Optional, Dict, Any, List

class SmartFTPProxy:
    def __init__(self, local_host: str, local_port: int, remote_host: str, remote_port: int):
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.socket = None
        self.data_connections: Dict[int, Dict[str, Any]] = {}
        self.running = False
        self.active_threads: List[threading.Thread] = []
        self.thread_lock = threading.Lock()
        
        # 解析并验证IP地址
        self.local_ip = self.resolve_hostname(local_host)
        if not self.local_ip:
            raise ValueError(f"无法解析本地主机名: {local_host}")
        
        print(f"[*] 本地地址 {local_host} 解析为 {self.local_ip}")
    
    def is_internal_ip(self, ip: str) -> bool:
        """检查是否为内部IP地址"""
        return re.match(r'^(10|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\.(?:\d{1,3}\.){2}\d{1,3}$', ip) is not None

    def resolve_hostname(self, hostname: str) -> str:
        """解析主机名为IP地址"""
        try:
            # 如果是IP地址，直接返回
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
                return hostname
            # 如果是localhost或主机名，解析为IP
            if hostname.lower() in ['localhost', '127.0.0.1']:
                return '127.0.0.1'
            # 解析其他主机名
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            print(f"[-] 警告: 无法解析主机名 '{hostname}'，使用原值")
            return hostname
    
    def start(self):
        """启动智能FTP代理服务器"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.local_host, self.local_port))
            self.socket.listen(5)
            # 设置非阻塞模式，这样accept就不会永久阻塞
            self.socket.setblocking(False)
            self.running = True
            
            print(f"[*] 智能FTP代理启动在 {self.local_host}:{self.local_port}")
            print(f"[*] 转发到 {self.remote_host}:{self.remote_port}")
            print(f"[*] 支持FTP主动和被动模式的数据连接代理")
            print(f"[*] 本地IP地址: {self.local_ip}")
            print(f"[*] 按 Ctrl+C 停止服务器")
            
            self.main_loop()
                    
        except Exception as e:
            print(f"[-] 启动代理服务器时出错: {e}")
            sys.exit(1)
        finally:
            self.stop()
    
    def main_loop(self):
        """主循环，使用select避免永久阻塞"""
        while self.running:
            try:
                # 使用select等待连接，超时1秒以便检查running标志
                readable, _, _ = select.select([self.socket], [], [], 1.0)
                
                if not self.running:
                    break
                    
                if self.socket in readable:
                    try:
                        client_socket, client_addr = self.socket.accept()
                        print(f"[+] 收到来自 {client_addr} 的控制连接")
                        
                        proxy_thread = threading.Thread(
                            target=self.handle_ftp_client,
                            args=(client_socket,)
                        )
                        proxy_thread.daemon = True
                        proxy_thread.start()
                        
                        with self.thread_lock:
                            self.active_threads.append(proxy_thread)
                        
                    except socket.error as e:
                        if self.running:
                            print(f"[-] 接受连接时出错: {e}")
                
                # 清理已完成的线程
                with self.thread_lock:
                    self.active_threads = [t for t in self.active_threads if t.is_alive()]
                        
            except KeyboardInterrupt:
                print("\n[*] 收到中断信号，正在关闭...")
                self.running = False
                break
            except Exception as e:
                if self.running:
                    print(f"[-] 主循环错误: {e}")
    
    def handle_ftp_client(self, client_socket: socket.socket):
        """处理FTP客户端连接"""
        server_socket = None
        
        try:
            # 设置控制连接超时和缓冲区大小
            client_socket.settimeout(300)  # 5分钟超时
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
            
            # 连接到远程FTP服务器
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10.0)  # 10秒连接超时
            server_socket.connect((self.remote_host, self.remote_port))
            server_socket.settimeout(300)  # 连接成功后设置5分钟超时
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
            
            print(f"[+] 控制连接建立: {client_socket.getpeername()} <-> {server_socket.getpeername()}")
            
            # 使用事件来协调线程退出
            stop_event = threading.Event()
            
            # 创建双向通信线程
            client_to_server_thread = threading.Thread(
                target=self.forward_ftp_control,
                args=(client_socket, server_socket, "CLIENT -> SERVER", stop_event)
            )
            server_to_client_thread = threading.Thread(
                target=self.forward_ftp_control, 
                args=(server_socket, client_socket, "SERVER -> CLIENT", stop_event)
            )
            
            client_to_server_thread.daemon = True
            server_to_client_thread.daemon = True
            
            client_to_server_thread.start()
            server_to_client_thread.start()
            
            # 等待任一线程结束
            while client_to_server_thread.is_alive() and server_to_client_thread.is_alive():
                time.sleep(0.1)
                if not self.running:
                    break
            
            # 设置停止事件
            stop_event.set()
            
            # 等待线程结束
            client_to_server_thread.join(timeout=2.0)
            server_to_client_thread.join(timeout=2.0)
            
        except socket.timeout:
            print(f"[-] 连接FTP服务器超时")
        except Exception as e:
            print(f"[-] 处理FTP客户端时出错: {e}")
        finally:
            # 确保socket关闭
            try:
                if client_socket:
                    client_socket.close()
                if server_socket:
                    server_socket.close()
            except:
                pass
            print(f"[-] FTP控制连接已关闭")
    
    def forward_ftp_control(self, source: socket.socket, destination: socket.socket, direction: str, stop_event: threading.Event):
        """转发FTP控制连接并解析修改命令"""
        last_activity = time.time()
        
        try:
            while self.running and not stop_event.is_set():
                # 检查连接超时（5分钟无活动）
                if time.time() - last_activity > 300:
                    print(f"[!] {direction} 控制连接超时，关闭连接")
                    break
                
                # 使用select检查是否有数据可读，避免永久阻塞
                try:
                    readable, _, _ = select.select([source], [], [], 1.0)
                    if stop_event.is_set():
                        break
                        
                    if source in readable:
                        data = source.recv(4096)
                        if not data:
                            print(f"[!] {direction} 连接被对端关闭")
                            break
                        
                        last_activity = time.time()  # 更新活动时间
                        
                        # 解析并修改FTP命令/响应
                        modified_data = self.process_ftp_data(data, direction, source.getpeername())
                        
                        print(f"[{direction}] 转发 {len(modified_data)} 字节")
                        self.display_ftp_content(modified_data, direction)
                        
                        try:
                            destination.send(modified_data)
                        except BrokenPipeError:
                            print(f"[-] {direction} 发送失败: 连接已断开")
                            break
                        except socket.error as e:
                            print(f"[-] {direction} 发送错误: {e}")
                            break
                except socket.timeout:
                    # select超时，继续循环检查running标志和超时
                    continue
                except socket.error as e:
                    if self.running and not stop_event.is_set():
                        print(f"[-] 转发FTP控制数据时出错 ({direction}): {e}")
                    break
                
        except Exception as e:
            if self.running and not stop_event.is_set():
                print(f"[-] 转发FTP控制数据时未知错误 ({direction}): {e}")
    
    def process_ftp_data(self, data: bytes, direction: str, client_addr: Tuple[str, int]) -> bytes:
        """处理FTP数据，修改PASV响应和PORT命令"""
        try:
            # 检查是否是有效的FTP命令/响应
            if len(data) < 2:
                return data
                
            text = data.decode('latin-1', errors='ignore')
            
            # 过滤掉控制字符（除了CR和LF）
            clean_text = ''.join(c for c in text if c.isprintable() or c in '\r\n')
            
            if direction == "SERVER -> CLIENT":
                # 处理服务器响应 - 修改PASV响应
                if clean_text.startswith('227'):
                    print(f"[!] 检测到PASV响应，正在修改...")
                    modified_text = self.modify_pasv_response(clean_text, client_addr[0])
                    return modified_text.encode('latin-1')
                    
            elif direction == "CLIENT -> SERVER":
                # 处理客户端命令 - 修改PORT命令
                if clean_text.upper().startswith('PORT'):
                    print(f"[!] 检测到PORT命令，正在修改...")
                    modified_text = self.modify_port_command(clean_text, client_addr[0])
                    return modified_text.encode('latin-1')
                
                # 处理EPSV命令（扩展被动模式）
                if clean_text.upper().startswith('EPSV'):
                    print(f"[!] 检测到EPSV命令，正在处理...")
                    # 对于EPSV，我们返回一个普通的PASV响应
                    return b"200 Using regular PASV instead of EPSV\r\n"
            
            return data
            
        except Exception as e:
            print(f"[-] 处理FTP数据时出错: {e}")
            return data
    
    def modify_pasv_response(self, response: str, client_ip: str) -> str:
        """修改PASV响应，将服务器地址改为代理地址"""
        # 解析原始PASV响应 (格式: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2))
        match = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', response)
        if not match:
            print(f"[-] 无法解析PASV响应: {response}")
            return response
        
        # 获取服务器原始IP和端口
        server_ip = '.'.join(match.group(1, 2, 3, 4))
        port_high = int(match.group(5))
        port_low = int(match.group(6))
        original_port = port_high * 256 + port_low
        
        print(f"[!] 服务器原始数据连接: {server_ip}:{original_port}")
        
        # 检查服务器IP是否为内部地址，如果是则使用代理IP
        if self.is_internal_ip(server_ip):
            print(f"[!] 检测到内部IP {server_ip}，使用代理IP {self.local_ip} 替换")
            effective_ip = self.local_ip
        else:
            effective_ip = server_ip
        
        # 创建代理数据连接监听
        proxy_data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_data_socket.bind(('0.0.0.0', 0))  # 任意可用端口
        proxy_data_socket.listen(1)
        proxy_data_socket.settimeout(5.0)  # 设置5秒超时
        proxy_port = proxy_data_socket.getsockname()[1]
        
        # 立即保存映射关系，避免竞争条件
        self.data_connections[proxy_port] = {
            'socket': proxy_data_socket,
            'original_server': (effective_ip, original_port),
            'type': 'PASV',
            'created': time.time()
        }
        
        # 启动数据连接处理线程
        data_thread = threading.Thread(
            target=self.handle_pasv_data_connection,
            args=(proxy_data_socket, proxy_port)
        )
        data_thread.daemon = True
        data_thread.start()
        
        with self.thread_lock:
            self.active_threads.append(data_thread)
        
        # 修改响应中的IP和端口
        proxy_ip_parts = self.local_ip.split('.')
        proxy_port_high = proxy_port // 256
        proxy_port_low = proxy_port % 256
        
        modified_response = re.sub(
            r'\(\d+,\d+,\d+,\d+,\d+,\d+\)',
            f'({proxy_ip_parts[0]},{proxy_ip_parts[1]},{proxy_ip_parts[2]},{proxy_ip_parts[3]},{proxy_port_high},{proxy_port_low})',
            response
        )
        
        print(f"[!] PASV响应已修改: 代理监听端口 {proxy_port} -> 服务器端口 {original_port}")
        return modified_response
    
    def modify_port_command(self, command: str, client_ip: str) -> str:
        """修改PORT命令，将客户端地址改为代理地址"""
        # 解析PORT命令 (格式: PORT h1,h2,h3,h4,p1,p2)
        parts = command.strip().split(' ')
        if len(parts) < 2:
            return command
            
        port_params = parts[1].split(',')
        if len(port_params) != 6:
            return command
        
        # 获取客户端原始IP和端口
        original_client_ip = '.'.join(port_params[0:4])
        port_high = int(port_params[4])
        port_low = int(port_params[5])
        original_port = port_high * 256 + port_low
        
        print(f"[!] 客户端原始数据连接: {original_client_ip}:{original_port}")
        
        # 检查客户端IP是否为内部地址，如果是则使用代理IP
        if self.is_internal_ip(original_client_ip):
            print(f"[!] 检测到内部IP {original_client_ip}，使用代理IP {self.local_ip} 替换")
            effective_ip = self.local_ip
        else:
            effective_ip = original_client_ip
        
        # 创建代理数据连接监听
        proxy_data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_data_socket.bind(('0.0.0.0', 0))
        proxy_data_socket.listen(1)
        proxy_data_socket.settimeout(10.0)  # 设置10秒超时
        proxy_port = proxy_data_socket.getsockname()[1]
        
        # 立即保存映射关系
        self.data_connections[proxy_port] = {
            'socket': proxy_data_socket,
            'original_client': (effective_ip, original_port),
            'type': 'PORT',
            'created': time.time()
        }
        
        # 启动数据连接处理线程
        data_thread = threading.Thread(
            target=self.handle_port_data_connection,
            args=(proxy_data_socket, proxy_port)
        )
        data_thread.daemon = True
        data_thread.start()
        
        with self.thread_lock:
            self.active_threads.append(data_thread)
        
        # 修改PORT命令中的IP和端口
        proxy_ip_parts = self.local_ip.split('.')
        proxy_port_high = proxy_port // 256
        proxy_port_low = proxy_port % 256
        
        modified_params = f"{proxy_ip_parts[0]},{proxy_ip_parts[1]},{proxy_ip_parts[2]},{proxy_ip_parts[3]},{proxy_port_high},{proxy_port_low}"
        modified_command = f"PORT {modified_params}\r\n"
        
        print(f"[!] PORT命令已修改: 代理监听端口 {proxy_port} -> 客户端端口 {original_port}")
        return modified_command
    
    def handle_pasv_data_connection(self, listen_socket: socket.socket, proxy_port: int):
        """处理PASV模式数据连接"""
        client_socket = None
        server_socket = None
        
        try:
            print(f"[+] 等待PASV数据连接在端口 {proxy_port}...")
            
            while self.running:
                try:
                    client_socket, client_addr = listen_socket.accept()
                    break
                except socket.timeout:
                    # 超时，检查是否继续运行
                    if not self.running:
                        return
                    continue
            
            if not self.running:
                return
                
            print(f"[+] PASV数据连接来自 {client_addr}")
            
            # 连接到服务器数据端口
            server_info = self.data_connections[proxy_port]['original_server']
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10.0)
            server_socket.connect(server_info)
            server_socket.settimeout(30)  # 数据连接超时30秒
            print(f"[+] 已连接到服务器数据端口 {server_info[1]}")
            
            # 双向转发数据
            self.forward_data_bidirectional(client_socket, server_socket, "PASV数据", proxy_port)
            
        except socket.timeout:
            print(f"[-] PASV数据连接超时，端口 {proxy_port}")
        except Exception as e:
            print(f"[-] 处理PASV数据连接时出错: {e}")
        finally:
            # 清理资源
            try:
                if client_socket:
                    client_socket.close()
                if server_socket:
                    server_socket.close()
                listen_socket.close()
            except:
                pass
            
            # 从连接字典中移除
            if proxy_port in self.data_connections:
                del self.data_connections[proxy_port]
                print(f"[-] PASV数据连接端口 {proxy_port} 已清理")
    
    def handle_port_data_connection(self, listen_socket: socket.socket, proxy_port: int):
        """处理PORT模式数据连接"""
        server_socket = None
        client_socket = None
        
        try:
            print(f"[+] 处理PORT数据连接，代理端口 {proxy_port}")
            
            if proxy_port not in self.data_connections:
                print(f"[-] 端口 {proxy_port} 不在连接字典中")
                return
                
            client_info = self.data_connections[proxy_port]['original_client']
            print(f"[+] 目标客户端: {client_info[0]}:{client_info[1]}")
            
            # 等待服务器连接
            print(f"[+] 等待服务器连接到代理端口 {proxy_port}...")
            
            while self.running:
                try:
                    server_socket, server_addr = listen_socket.accept()
                    break
                except socket.timeout:
                    # 超时，检查是否继续运行
                    if not self.running:
                        return
                    continue
            
            if not self.running:
                return
                
            print(f"[+] 服务器已连接: {server_addr}")
            
            # 连接到客户端数据端口
            print(f"[+] 连接到客户端数据端口 {client_info[1]}...")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)
            client_socket.connect(client_info)
            client_socket.settimeout(30)  # 数据连接超时30秒
            print(f"[+] 成功连接到客户端数据端口")
            
            # 开始双向数据转发
            print(f"[+] 开始PORT模式数据转发")
            self.forward_data_bidirectional(server_socket, client_socket, "PORT数据", proxy_port)
            
        except socket.timeout:
            print(f"[-] PORT数据连接超时，端口 {proxy_port}")
        except ConnectionRefusedError:
            print(f"[-] 无法连接到客户端数据端口 {client_info[1]}")
        except Exception as e:
            print(f"[-] 处理PORT数据连接时出错: {e}")
        finally:
            # 清理资源
            try:
                if server_socket:
                    server_socket.close()
                if client_socket:
                    client_socket.close()
                listen_socket.close()
            except:
                pass
            
            # 从连接字典中移除
            if proxy_port in self.data_connections:
                del self.data_connections[proxy_port]
                print(f"[-] PORT数据连接清理完成")
    
    def forward_data_bidirectional(self, socket1: socket.socket, socket2: socket.socket, connection_type: str, proxy_port: int):
        """双向转发数据"""
        def forward(source: socket.socket, destination: socket.socket, direction: str):
            try:
                while self.running:
                    # 使用select检查数据可用性
                    try:
                        readable, _, _ = select.select([source], [], [], 1.0)
                        if not self.running:
                            break
                            
                        if source in readable:
                            data = source.recv(8192)
                            if not data:
                                print(f"[{connection_type}] {direction}: 连接关闭")
                                break
                            destination.send(data)
                            print(f"[{connection_type}] {direction}: 转发 {len(data)} 字节")
                    except socket.timeout:
                        continue
                    except socket.error as e:
                        print(f"[-] 数据转发错误 ({direction}): {e}")
                        break
            except Exception as e:
                if self.running:
                    print(f"[-] 数据转发线程错误 ({direction}): {e}")
        
        # 创建两个方向的转发线程
        thread1 = threading.Thread(
            target=forward,
            args=(socket1, socket2, "A -> B")
        )
        thread2 = threading.Thread(
            target=forward,
            args=(socket2, socket1, "B -> A")
        )
        
        thread1.daemon = True
        thread2.daemon = True
        
        thread1.start()
        thread2.start()
        
        # 等待任一线程结束
        thread1.join(timeout=30)  # 最多等待30秒
        thread2.join(timeout=5)   # 第二个线程应该很快结束
        
        print(f"[-] {connection_type} 转发结束")
        
        # 确保从连接字典中移除
        if proxy_port in self.data_connections:
            del self.data_connections[proxy_port]
            print(f"[-] 数据连接端口 {proxy_port} 映射已删除")
    
    def display_ftp_content(self, data: bytes, direction: str):
        """显示FTP内容"""
        try:
            text = data.decode('latin-1', errors='replace').strip()
            lines = text.split('\r\n')
            for line in lines:
                if line:
                    print(f"    {direction}: {line}")
        except:
            # 如果是二进制数据，显示十六进制
            hex_str = ' '.join([f'{b:02x}' for b in data[:20]])
            if len(data) > 20:
                hex_str += ' ...'
            print(f"    {direction} [二进制 {len(data)}字节]: {hex_str}")
    
    def stop(self):
        """停止代理服务器"""
        print("\n[*] 正在停止FTP代理服务器...")
        self.running = False
        
        # 关闭主监听socket
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        # 关闭所有数据连接
        for port, info in list(self.data_connections.items()):
            try:
                info['socket'].close()
            except:
                pass
        
        self.data_connections.clear()
        
        # 等待活动线程结束
        print("[*] 等待活动线程结束...")
        for thread in self.active_threads:
            try:
                thread.join(timeout=2.0)
            except:
                pass
        
        self.active_threads.clear()
        print("[*] FTP代理服务器已完全停止")

def main():
    # 默认配置
    LOCAL_HOST = "127.0.0.1"
    LOCAL_PORT = 2121
    REMOTE_HOST = "127.0.0.1"
    REMOTE_PORT = 21
    
    # 从命令行参数获取配置
    if len(sys.argv) >= 5:
        LOCAL_HOST = sys.argv[1]
        LOCAL_PORT = int(sys.argv[2])
        REMOTE_HOST = sys.argv[3]
        REMOTE_PORT = int(sys.argv[4])
    else:
        print("用法: python smart_ftp_proxy.py <本地IP> <本地端口> <远程IP> <远程端口>")
        print(f"使用默认配置: {LOCAL_HOST}:{LOCAL_PORT} -> {REMOTE_HOST}:{REMOTE_PORT}")
    
    try:
        proxy = SmartFTPProxy(LOCAL_HOST, LOCAL_PORT, REMOTE_HOST, REMOTE_PORT)
        proxy.start()
            
    except KeyboardInterrupt:
        print("\n[*] 收到中断信号，正在关闭...")
    except Exception as e:
        print(f"[-] 初始化代理服务器失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()