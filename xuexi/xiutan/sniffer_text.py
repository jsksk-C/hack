import socket
import os

def test_raw_socket():
    """测试原始套接字的基本功能"""
    try:
        # 尝试创建ICMP原始套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(3.0)
        print("ICMP原始套接字创建成功")
        sock.close()
        return True
    except Exception as e:
        print(f"ICMP原始套接字失败: {e}")
    
    try:
        # 尝试创建IP原始套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.settimeout(3.0)
        print("IP原始套接字创建成功")
        sock.close()
        return True
    except Exception as e:
        print(f"IP原始套接字失败: {e}")
    
    return False

if __name__ == '__main__':
    if os.name != 'nt':
        print("此测试仅适用于Windows系统")
    else:
        print("测试原始套接字功能...")
        if test_raw_socket():
            print("原始套接字功能正常")
        else:
            print("原始套接字功能异常")