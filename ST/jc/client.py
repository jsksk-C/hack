import socket

# 创建 socket 对象
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # 连接到服务器
    s2.connect(("127.0.0.1", 2345))
    print("已连接到服务器")
    
    # 接收数据
    data = s2.recv(1024)
    
    # 将 bytes 类型解码为字符串
    decoded_data = data.decode()
    
    # 关闭连接
    s2.close()
    
    print(f"从服务器接收到的数据: {decoded_data}")
    
except ConnectionRefusedError:
    print("连接被拒绝，请确保服务器已启动")
except Exception as e:
    print(f"发生错误: {e}")