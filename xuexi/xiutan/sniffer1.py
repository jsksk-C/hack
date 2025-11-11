import ctypes
from ctypes import wintypes
import socket

def simple_promiscuous_mode():
    """简化版本的混杂模式设置"""
    # 检查管理员权限
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("请以管理员权限运行!")
        return False
    
    # 定义常量
    SIO_RCVALL = 0x98000001
    RCVALL_ON = ctypes.c_ulong(1)
    ws2_32 = ctypes.windll.ws2_32
    
    try:
        # 创建并配置原始套接字
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        local_ip = '172.20.187.118'
        raw_socket.bind((local_ip, 0))
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # 设置混杂模式
        in_buffer = RCVALL_ON
        bytes_returned = wintypes.DWORD()
        
        result = ws2_32.WSAIoctl(
            raw_socket.fileno(),
            SIO_RCVALL,
            ctypes.byref(in_buffer),
            ctypes.sizeof(ctypes.c_ulong),
            None,
            0,
            ctypes.byref(bytes_returned),
            None,
            None
        )
        
        if result == 0:
            print("✅ 混杂模式启用成功!")
            return True
        else:
            print(f"❌ 失败，错误代码: {ws2_32.WSAGetLastError()}")
            return False
            
    except Exception as e:
        print(f"错误: {e}")
        return False

if __name__ == "__main__":
    simple_promiscuous_mode()


"""import ctypes
from ctypes import wintypes

# 定义必要的常量和结构体
RCVALL_ON = ctypes.c_ulong(1)  # 注意这里定义为c_ulong

# ... (创建并绑定原始套接字的代码)

# 设置输入参数
in_buffer = ctypes.c_ulong(RCVALL_ON)  # 传入RCVALL_ON的值
in_buffer_size = ctypes.sizeof(ctypes.c_ulong)  # 计算c_ulong的大小
bytes_returned = wintypes.DWORD()  # 正确初始化bytes_returned

# 调用WSAIoctl
result = ws2_32.WSAIoctl(
    raw_socket.fileno(),        # 套接字句柄
    SIO_RCVALL,                 # 控制代码:cite[9]
    ctypes.byref(in_buffer),    # 传递输入缓冲区的地址:cite[3]
    in_buffer_size,             # 输入缓冲区的大小
    None,                       # 本例不使用输出缓冲区
    0,                          # 输出缓冲区大小为0
    ctypes.byref(bytes_returned), # 传递bytes_returned的地址
    None,                       # 同步调用，重叠结构为None
    None                        # 同步调用，完成例程为None
)          帮我完善windows11系统  调用WSAIoctl 设置混杂模式，  验证能不能成功。

"""