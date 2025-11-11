"""通过连接外部服务器获取本机IP  方法2: 获取主机名对应的IP和 """
import ctypes
from ctypes import wintypes
import socket
import struct
import sys

def get_local_ip():
    """
    获取本机真实的外部网络IP地址
    """
    try:
        # 方法1: 通过连接外部服务器获取本机IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return local_ip
    except:
        try:
            # 方法2: 获取主机名对应的IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return local_ip
        except:
            return "127.0.0.1"

def get_all_network_interfaces():
    """
    获取所有网络接口的IP地址
    """
    interfaces = []
    try:
        # 获取所有网络接口信息
        hostname = socket.gethostname()
        ip_list = socket.getaddrinfo(hostname, None)
        
        for ip in ip_list:
            ip_addr = ip[4][0]
            if ip_addr not in interfaces and not ip_addr.startswith('127.'):
                interfaces.append(ip_addr)
        
        return interfaces
    except:
        return []

def enable_promiscuous_mode(interface_ip=None):
    """
    在Windows 11系统上启用网卡混杂模式
    interface_ip: 指定要监听的网络接口IP
    """
    # 检查管理员权限
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("错误: 需要以管理员权限运行此脚本")
        return False
    
    # 定义必要的常量和结构体
    SIO_RCVALL = 0x98000001
    RCVALL_ON = ctypes.c_ulong(1)
    
    # 加载ws2_32.dll
    ws2_32 = ctypes.windll.ws2_32
    
    try:
        # 获取要绑定的IP地址
        if interface_ip:
            local_ip = interface_ip
            print(f"📡 使用指定的网络接口: {local_ip}")
        else:
            # 自动获取本地IP
            local_ip = get_local_ip()
            print(f"📡 自动检测到网络接口: {local_ip}")
        
        # 显示所有可用的网络接口
        all_interfaces = get_all_network_interfaces()
        if all_interfaces:
            print("🔍 所有可用的网络接口:")
            for i, ip in enumerate(all_interfaces):
                print(f"   {i+1}. {ip}")
        
        # 创建原始套接字
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        
        print(f"🔧 绑定到IP地址: {local_ip}")
        raw_socket.bind((local_ip, 0))
        
        # 设置套接字选项，包含IP头
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # 设置网卡为混杂模式
        in_buffer = RCVALL_ON
        in_buffer_size = ctypes.sizeof(ctypes.c_ulong)
        bytes_returned = wintypes.DWORD()
        
        result = ws2_32.WSAIoctl(
            raw_socket.fileno(),
            SIO_RCVALL,
            ctypes.byref(in_buffer),
            in_buffer_size,
            None,
            0,
            ctypes.byref(bytes_returned),
            None,
            None
        )
        
        if result == 0:
            print("✅ 成功启用网卡混杂模式!")
            print("⚠️  注意: 程序运行期间将捕获所有经过网卡的数据包")
            
            # 开始捕获数据包
            capture_packets(raw_socket)
            return True
        else:
            error_code = ws2_32.WSAGetLastError()
            print(f"❌ 启用混杂模式失败，错误代码: {error_code}")
            return False
            
    except socket.error as e:
        print(f"❌ 套接字错误: {e}")
        print("可能的原因:")
        print("1. IP地址绑定错误")
        print("2. 没有管理员权限") 
        print("3. 防火墙或杀毒软件阻止")
        print("4. 网卡不支持混杂模式")
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
                raw_socket.settimeout(1.0)
                packet, addr = raw_socket.recvfrom(65535)
                
                if packet:
                    packet_count += 1
                    print(f"\n📦 数据包 #{packet_count}, 长度: {len(packet)} 字节")
                    
                    # 解析IP头部
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
                        
                        # 如果是UDP协议  
                        elif protocol == 17:  # UDP
                            print("   🔊 这是一个UDP数据包")
                            
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

def main():
    """
    主函数
    """
    print("=" * 50)
    print("Windows 11 网卡混杂模式设置工具")
    print("=" * 50)
    
    if not check_system_compatibility():
        return
    
    print("\n📝 功能说明:")
    print("• 此工具将设置网卡为混杂模式")
    print("• 混杂模式下，网卡将接收所有经过的数据包")
    print("• 需要管理员权限运行")
    
    # 让用户选择是否指定IP
    print("\n🌐 网络接口选择:")
    print("1. 自动检测网络接口")
    print("2. 手动指定IP地址")
    
    choice = input("请选择 (1/2): ").strip()
    
    interface_ip = None
    if choice == "2":
        interface_ip = input("请输入要监听的IP地址 (例如 172.20.187.118): ").strip()
        if not interface_ip:
            print("⚠️  未输入IP地址，使用自动检测")
    
    print("\n开始设置混杂模式...")
    success = enable_promiscuous_mode(interface_ip)
    
    if success:
        print("\n🎉 混杂模式设置成功!")
    else:
        print("\n❌ 设置失败")

def check_system_compatibility():
    """检查系统兼容性"""
    if sys.platform != "win32":
        print("❌ 此脚本仅适用于Windows系统")
        return False
    return True

if __name__ == "__main__":
    try:
        main()
        input("\n按 Enter 键退出...")
    except KeyboardInterrupt:
        print("\n⏹️  用户中断程序")
    except Exception as e:
        print(f"\n❌ 程序执行出错: {e}")