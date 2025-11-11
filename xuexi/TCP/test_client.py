# test_client.py
import socket

def test_proxy():
    # 通过代理连接
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 8888))
    
    # 发送测试数据
    test_data = "HELLO word!"
    client.send(test_data.encode())
    
    # 接收响应
    response = client.recv(1024)
    print(f"发送: {test_data}")
    print(f"收到: {response.decode()}")
    
    client.close()

if __name__ == "__main__":
    test_proxy()