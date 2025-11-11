import socket

# 创建 socket 对象
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 绑定地址和端口
s1.bind(("127.0.0.1", 2345))

# 开始监听，设置最大连接数
s1.listen(5)
print("服务器已启动，等待客户端连接...")

str_msg = "Hello world"

try:
    while True:
        # 等待客户端连接
        conn, address = s1.accept()
        print(f"一个新的连接来自: {address}")
        
        # 发送消息给客户端
        conn.send(str_msg.encode())
        
        # 关闭当前连接
        conn.close()
        
except KeyboardInterrupt:
    print("\n服务器关闭")
finally:
    # 关闭服务器 socket
    s1.close()
