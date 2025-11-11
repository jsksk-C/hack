import socket
import sys
import threading
import time

def receive_data(client_socket):
    while True:
        try:
            data = client_socket.recv(1024).decode('utf-8', errors='ignore')
            if not data:
                break
            print(data, end='')
            sys.stdout.flush()
        except:
            break

def main():
    if len(sys.argv) != 2:
        print("Usage: python listener.py <port>")
        print("Example: python listener.py 1691")
        sys.exit(1)
    
    port = int(sys.argv[1])
    host = '0.0.0.0'
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((host, port))
        s.listen(5)
        print(f"[+] Listening on {host}:{port}")
        print("[+] Waiting for connection...")
        
        client_socket, client_address = s.accept()
        print(f"[+] Connection from {client_address}")
        print("[+] Reverse shell connected! Type commands below.")
        
        # 启动接收线程
        recv_thread = threading.Thread(target=receive_data, args=(client_socket,))
        recv_thread.daemon = True
        recv_thread.start()
        
        # 发送命令
        while True:
            try:
                cmd = input()
                if cmd.strip().lower() == 'exit':
                    break
                client_socket.send((cmd + '\n').encode())
            except KeyboardInterrupt:
                print("\n[+] Closing connection...")
                break
            except Exception as e:
                print(f"\n[!] Error: {e}")
                break
                
    except Exception as e:
        print(f"[!] Failed to bind port {port}: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass
        s.close()
        print("[+] Listener closed")

if __name__ == "__main__":
    main()