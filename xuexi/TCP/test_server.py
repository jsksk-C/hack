# test_server.py
import socket
import threading

def test_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 9999))
    server.listen(5)
    print("测试服务器启动在 127.0.0.1:9999")
    
    while True:
        client, addr = server.accept()
        print(f"测试服务器收到连接: {addr}")
        
        def handle_client(client_socket):
            data = client_socket.recv(1024)
            print(f"测试服务器收到: {data.decode()}")
            response = f"ECHO: {data.decode()}"
            client_socket.send(response.encode())
            client_socket.close()
        
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

if __name__ == "__main__":
    test_server()