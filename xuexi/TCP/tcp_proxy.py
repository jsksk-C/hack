import socket
import threading
import sys

class TCPProxy:
    def __init__(self, local_host, local_port, remote_host, remote_port):
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.socket = None
        
    def start(self):
        """启动代理服务器"""
        try:
            # 创建服务器套接字
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.local_host, self.local_port))
            self.socket.listen(5)
            
            print(f"[*] TCP代理启动在 {self.local_host}:{self.local_port}")
            print(f"[*] 转发到 {self.remote_host}:{self.remote_port}")
            
            while True:
                try:
                    client_socket, client_addr = self.socket.accept()
                    print(f"[+] 收到来自 {client_addr} 的连接")
                    
                    # 为每个客户端创建新线程
                    proxy_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket,)
                    )
                    proxy_thread.daemon = True
                    proxy_thread.start()
                    
                except Exception as e:
                    print(f"[-] 接受连接时出错: {e}")
                    
        except Exception as e:
            print(f"[-] 启动代理服务器时出错: {e}")
            sys.exit(1)
            
    def handle_client(self, client_socket):
        """处理客户端连接"""
        remote_socket = None
        
        try:
            # 连接到远程服务器
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((self.remote_host, self.remote_port))
            
            # 创建两个线程来处理双向数据流
            client_to_remote = threading.Thread(
                target=self.forward_data,
                args=(client_socket, remote_socket, "客户端 -> 服务器")
            )
            remote_to_client = threading.Thread(
                target=self.forward_data,
                args=(remote_socket, client_socket, "服务器 -> 客户端")
            )
            
            client_to_remote.daemon = True
            remote_to_client.daemon = True
            
            client_to_remote.start()
            remote_to_client.start()
            
            # 等待线程结束
            client_to_remote.join()
            remote_to_client.join()
            
        except Exception as e:
            print(f"[-] 处理客户端时出错: {e}")
        finally:
            # 关闭连接
            if client_socket:
                client_socket.close()
            if remote_socket:
                remote_socket.close()
            print(f"[-] 连接已关闭")
            
    def forward_data(self, source, destination, direction):
        """转发数据并在控制台显示"""
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break
                
                print(f"[{direction}] 转发 {len(data)} 字节")
                # 显示数据内容（前50字节）
                if len(data) > 0:
                    hex_str = ' '.join([f'{b:02x}' for b in data[:50]])
                    ascii_str = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data[:50]])
                    print(f"  十六进制: {hex_str}")
                    print(f"  ASCII: {ascii_str}")
                
                destination.send(data)
        except Exception as e:
            print(f"[-] 转发数据时出错 ({direction}): {e}")
        
    def stop(self):
        """停止代理服务器"""
        if self.socket:
            self.socket.close()
            print("[*] 代理服务器已停止")

def main():
    # 默认配置
    LOCAL_HOST = "127.0.0.1"
    LOCAL_PORT = 8888
    REMOTE_HOST = "www.example.com"
    REMOTE_PORT = 80
    
    # 从命令行参数获取配置
    if len(sys.argv) >= 5:
        LOCAL_HOST = sys.argv[1]
        LOCAL_PORT = int(sys.argv[2])
        REMOTE_HOST = sys.argv[3]
        REMOTE_PORT = int(sys.argv[4])
    else:
        print("用法: python tcp_proxy.py <本地IP> <本地端口> <远程IP> <远程端口>")
        print(f"使用默认配置: {LOCAL_HOST}:{LOCAL_PORT} -> {REMOTE_HOST}:{REMOTE_PORT}")
    
    # 创建并启动代理
    proxy = TCPProxy(LOCAL_HOST, LOCAL_PORT, REMOTE_HOST, REMOTE_PORT)
    
    # 在单独的线程中启动代理
    proxy_thread = threading.Thread(target=proxy.start)
    proxy_thread.daemon = True
    proxy_thread.start()
    
    try:
        # 主线程等待用户输入或Ctrl+C
        while proxy_thread.is_alive():
            proxy_thread.join(0.1)  # 短暂等待，定期检查
    except KeyboardInterrupt:
        print("\n[*] 收到中断信号，正在关闭...")
        proxy.stop()

if __name__ == "__main__":
    main()

