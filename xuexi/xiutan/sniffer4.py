"""  手动直接绑定 网络接口"""

import ctypes
from ctypes import wintypes
import socket
import struct
import sys

def enable_promiscuous_mode():
    """
    在Windows 11系统上启用网卡混杂模式
    返回: True表示成功，False表示失败
    """
    # 检查管理员权限
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("错误: 需要以管理员权限运行此脚本")
        return False
    
    # 定义必要的常量和结构体
    SIO_RCVALL = 0x98000001  # 启用接收所有数据包的控制代码
    RCVALL_ON = ctypes.c_ulong(1)
    
    # 加载ws2_32.dll
    ws2_32 = ctypes.windll.ws2_32
    
    try:
        # 创建原始套接字
        # AF_INET: IPv4, SOCK_RAW: 原始套接字, IPPROTO_IP: IP协议
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        
        # 绑定到指定的本地IP地址
        # 修改这里：直接使用你的实际IP地址
        local_ip = "172.20.187.118"  # 你的实际IP地址
        
        print(f"📡 绑定到网络接口: {local_ip}")
        raw_socket.bind((local_ip, 0))
        
        # 设置套接字选项，包含IP头
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # 设置网卡为混杂模式
        in_buffer = RCVALL_ON
        in_buffer_size = ctypes.sizeof(ctypes.c_ulong)
        bytes_returned = wintypes.DWORD()
        
        # 调用WSAIoctl设置混杂模式
        result = ws2_32.WSAIoctl(
            raw_socket.fileno(),        # 套接字句柄
            SIO_RCVALL,                 # 控制代码
            ctypes.byref(in_buffer),    # 输入缓冲区
            in_buffer_size,             # 输入缓冲区大小
            None,                       # 输出缓冲区
            0,                          # 输出缓冲区大小
            ctypes.byref(bytes_returned), # 返回的字节数
            None,                       # 重叠结构
            None                        # 完成例程
        )
        
        if result == 0:
            print("✅ 成功启用网卡混杂模式!")
            print("⚠️  注意: 程序运行期间将捕获所有经过网卡的数据包")
            
            # 开始数据包捕获
            capture_packets(raw_socket)
            return True
        else:
            error_code = ws2_32.WSAGetLastError()
            print(f"❌ 启用混杂模式失败，错误代码: {error_code}")
            return False
            
    except socket.error as e:
        print(f"❌ 套接字错误: {e}")
        print("可能的原因:")
        print("1. 没有管理员权限")
        print("2. 防火墙或杀毒软件阻止")
        print("3. 网卡不支持混杂模式")
        print("4. 指定的IP地址不存在或不可用")
        return False
    except Exception as e:
        print(f"❌ 未知错误: {e}")
        return False

def capture_packets(raw_socket):
    """
    捕获和分析数据包
    """
    print("\n🎯 开始捕获数据包...")
    print("按 Ctrl+C 停止捕获")
    
    try:
        packet_count = 0
        while True:
            try:
                # 设置超时，避免无限等待
                raw_socket.settimeout(1.0)
                packet, addr = raw_socket.recvfrom(65535)
                
                if packet:
                    packet_count += 1
                    print(f"\n📦 数据包 #{packet_count}, 长度: {len(packet)} 字节")
                    
                    # 解析IP头部（前20字节）
                    if len(packet) >= 20:
                        ip_header = packet[:20]
                        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                        
                        version_ihl = iph[0]
                        version = version_ihl >> 4
                        ihl = version_ihl & 0xF
                        ip_header_length = ihl * 4
                        
                        protocol = iph[6]
                        src_ip = socket.inet_ntoa(iph[8])
                        dst_ip = socket.inet_ntoa(iph[9])
                        ttl = iph[5]
                        
                        print(f"   📡 {src_ip} -> {dst_ip}")
                        print(f"   🔧 协议: {get_protocol_name(protocol)} (IPv{version})")
                        print(f"   ⏱️  TTL: {ttl}")
                        
                        # 如果是ICMP协议(ping)
                        if protocol == 1:  # ICMP
                            print("   🎯 这是一个ICMP数据包(PING)!")
                            # 解析ICMP头部
                            if len(packet) >= ip_header_length + 8:
                                icmp_header = packet[ip_header_length:ip_header_length+8]
                                icmph = struct.unpack('!BBHHH', icmp_header)
                                icmp_type = icmph[0]
                                icmp_code = icmph[1]
                                print(f"   💫 ICMP类型: {icmp_type}, 代码: {icmp_code}")
                        
                        # 如果是TCP协议
                        elif protocol == 6:  # TCP
                            print("   🔗 这是一个TCP数据包")
                            # 解析TCP头部
                            if len(packet) >= ip_header_length + 20:
                                tcp_header = packet[ip_header_length:ip_header_length+20]
                                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                                src_port = tcph[0]
                                dst_port = tcph[1]
                                print(f"   🚪 源端口: {src_port} -> 目标端口: {dst_port}")
                        
                        # 如果是UDP协议  
                        elif protocol == 17:  # UDP
                            print("   🔊 这是一个UDP数据包")
                            # 解析UDP头部
                            if len(packet) >= ip_header_length + 8:
                                udp_header = packet[ip_header_length:ip_header_length+8]
                                udph = struct.unpack('!HHHH', udp_header)
                                src_port = udph[0]
                                dst_port = udph[1]
                                print(f"   🚪 源端口: {src_port} -> 目标端口: {dst_port}")
                            
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                print("\n⏹️  用户停止数据包捕获")
                break
                
    except Exception as e:
        print(f"数据包捕获出错: {e}")

def get_protocol_name(protocol_num):
    """
    根据协议号返回协议名称
    """
    protocol_map = {
        1: "ICMP",
        6: "TCP", 
        17: "UDP",
        2: "IGMP",
        41: "IPv6",
        47: "GRE",
        50: "ESP",
        51: "AH"
    }
    return protocol_map.get(protocol_num, f"未知({protocol_num})")

def check_system_compatibility():
    """
    检查系统兼容性
    """
    print("🔍 检查系统兼容性...")
    
    # 检查操作系统
    if sys.platform != "win32":
        print("❌ 此脚本仅适用于Windows系统")
        return False
    
    # 检查Python版本
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
        print("❌ 需要Python 3.6或更高版本")
        return False
    
    print("✅ 系统兼容性检查通过")
    return True

def main():
    """
    主函数
    """
    print("=" * 50)
    print("Windows 11 网卡混杂模式设置工具")
    print("=" * 50)
    
    # 系统兼容性检查
    if not check_system_compatibility():
        return
    
    print("\n📝 功能说明:")
    print("• 此工具将设置网卡为混杂模式")
    print("• 混杂模式下，网卡将接收所有经过的数据包")
    print("• 需要管理员权限运行")
    print("• 主要用于网络监控和调试")
    print(f"• 当前绑定IP: 172.20.187.118")
    
    input("\n按 Enter 键继续...")
    
    # 启用混杂模式
    success = enable_promiscuous_mode()
    
    if success:
        print("\n🎉 混杂模式设置成功!")
        print("💡 提示: 保持程序运行以维持混杂模式")
        print("       关闭程序将自动恢复普通模式")
    else:
        print("\n💡 故障排除建议:")
        print("1. 以管理员身份运行此脚本")
        print("2. 暂时禁用防火墙和杀毒软件")
        print("3. 检查网卡驱动是否正常")
        print("4. 确认IP地址 172.20.187.118 是正确的本机IP")

if __name__ == "__main__":
    try:
        main()
        input("\n按 Enter 键退出...")
    except KeyboardInterrupt:
        print("\n\n⏹️  用户中断程序")
    except Exception as e:
        print(f"\n❌ 程序执行出错: {e}")