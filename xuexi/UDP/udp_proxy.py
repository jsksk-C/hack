from concurrent.futures import ThreadPoolExecutor
import socket
import sys
import threading
import time
from collections import defaultdict

class WindowsUDPProxy:
    def __init__(self, listen_port, target_host, target_port):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.running = False
        
        # 用于跟踪客户端会话
        self.client_stats = defaultdict(lambda: {'requests': 0, 'last_active': 0})
        
        # 创建监听socket
        self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Windows UDP socket 设置
        try:
            # 设置SO_REUSEADDR以便快速重启
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except:
            pass  # 某些系统可能不支持
        
        # 设置接收超时，允许优雅退出
        self.proxy_socket.settimeout(1.0)
        
        try:
            self.proxy_socket.bind(('0.0.0.0', self.listen_port))
            print(f"[+] UDP代理启动: 0.0.0.0:{self.listen_port} -> {self.target_host}:{self.target_port}")
        except OSError as e:
            print(f"[-] 绑定端口失败: {e}")
            print(f"[-] 请检查端口 {self.listen_port} 是否被其他程序占用")
            sys.exit(1)
        
        # 线程池配置
        self.max_workers = 20
        self.executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="UDPProxyWorker"
        )
        
        # 用于优雅关闭的信号
        self._shutdown_event = threading.Event()
        
        print(f"[+] 代理初始化完成，最大工作线程: {self.max_workers}")

    def forward_request(self, data, client_addr):
        """转发请求到目标服务器并返回响应"""
        target_socket = None
        try:
            # 更新客户端统计
            self.client_stats[client_addr]['requests'] += 1
            self.client_stats[client_addr]['last_active'] = time.time()
            
            print(f"[→] 转发 {client_addr} -> {self.target_host}:{self.target_port}, 大小: {len(data)}字节")
            
            # 创建目标socket
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            target_socket.settimeout(3.0)  # 3秒超时
            
            # 发送到目标服务器
            start_time = time.time()
            target_socket.sendto(data, (self.target_host, self.target_port))
            
            # 接收响应
            response, server_addr = target_socket.recvfrom(4096)
            response_time = (time.time() - start_time) * 1000  # 毫秒
            
            # 返回响应给客户端
            self.proxy_socket.sendto(response, client_addr)
            
            print(f"[←] 响应 {client_addr} <- {server_addr}, 大小: {len(response)}字节, 耗时: {response_time:.1f}ms")
            
            return True
            
        except socket.timeout:
            print(f"[-] 目标服务器响应超时 ({self.target_host}:{self.target_port})")
            return False
            
        except Exception as e:
            print(f"[-] 转发错误 {client_addr}: {e}")
            return False
            
        finally:
            # 确保关闭目标socket
            if target_socket:
                try:
                    target_socket.close()
                except:
                    pass

    def start(self):
        """启动代理服务"""
        if self.running:
            print("[-] 代理已经在运行中")
            return
            
        self.running = True
        self._shutdown_event.clear()
        
        print("[*] UDP代理服务运行中...")
        print("[*] 按 Ctrl+C 停止服务")
        print(f"[*] 监听端口: {self.listen_port}")
        print(f"[*] 目标服务器: {self.target_host}:{self.target_port}")
        
        processed_requests = 0
        
        try:
            while self.running and not self._shutdown_event.is_set():
                try:
                    # 接收客户端数据
                    data, client_addr = self.proxy_socket.recvfrom(4096)
                    processed_requests += 1
                    
                    # 打印接收信息（每10个请求显示一次统计）
                    if processed_requests % 10 == 0:
                        active_clients = len([addr for addr, stats in self.client_stats.items() 
                                            if time.time() - stats['last_active'] < 60])
                        print(f"[统计] 已处理请求: {processed_requests}, 活跃客户端: {active_clients}")
                    
                    # 提交到线程池处理
                    self.executor.submit(self.forward_request, data, client_addr)
                    
                except socket.timeout:
                    # 超时是正常的，用于检查关闭信号
                    continue
                    
                except OSError as e:
                    if self.running:
                        print(f"[-] 接收错误: {e}")
                    break
                    
        except KeyboardInterrupt:
            print("\n[!] 收到中断信号，正在关闭...")
            
        except Exception as e:
            print(f"[-] 代理运行错误: {e}")
            
        finally:
            self.stop()

    def stop(self):
        """停止代理服务"""
        if not self.running:
            return
            
        print("\n[!] 正在停止代理服务...")
        self.running = False
        self._shutdown_event.set()
        
        # 关闭线程池 - 修复了timeout参数问题
        try:
            # 先尝试取消所有待处理的任务
            self.executor.shutdown(wait=False)
            print("[+] 线程池已关闭（不等待任务完成）")
        except Exception as e:
            print(f"[-] 线程池关闭异常: {e}")
            try:
                # 备用关闭方法
                self.executor.shutdown(wait=True)
                print("[+] 线程池已关闭（等待任务完成）")
            except Exception as e2:
                print(f"[-] 线程池备用关闭也失败: {e2}")
        
        # 关闭socket
        try:
            self.proxy_socket.close()
            print("[+] Socket已关闭")
        except Exception as e:
            print(f"[-] Socket关闭异常: {e}")
        
        # 打印统计信息
        total_requests = sum(stats['requests'] for stats in self.client_stats.values())
        unique_clients = len(self.client_stats)
        print(f"[统计] 总处理请求: {total_requests}, 唯一客户端: {unique_clients}")
        
        print("[+] 代理服务已完全停止")

def main():
    if len(sys.argv) != 4:
        print("Windows UDP代理工具")
        print("用法: python udp_proxy.py <监听端口> <目标地址> <目标端口>")
        print("示例: python udp_proxy.py 5353 8.8.8.8 53")
        print("示例: python udp_proxy.py 8888 192.168.1.100 5060")
        sys.exit(1)

    try:
        listen_port = int(sys.argv[1])
        target_host = sys.argv[2]
        target_port = int(sys.argv[3])

        # 参数验证
        if not (1 <= listen_port <= 65535):
            print("[-] 监听端口必须在1-65535范围内")
            sys.exit(1)

        if not (1 <= target_port <= 65535):
            print("[-] 目标端口必须在1-65535范围内")
            sys.exit(1)

        # 创建并启动代理
        proxy = WindowsUDPProxy(listen_port, target_host, target_port)
        
        # 启动代理
        proxy.start()

    except KeyboardInterrupt:
        print("\n[!] 用户中断程序")
    except ValueError as e:
        print(f"[-] 参数错误: {e}")
        print("[-] 端口必须是数字")
        sys.exit(1)
    except Exception as e:
        print(f"[-] 启动错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()