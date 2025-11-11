"""  直接获取所有网络接口，  选择网络接口并选择监听的地址"""
import ctypes
from ctypes import wintypes
import socket
import struct
import sys
import psutil  # 需要安装: pip install psutil

def get_network_interfaces():
    """获取所有网络接口信息"""
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    
    for interface_name, interface_addresses in addrs.items():
        # 检查接口状态
        if interface_name in stats and stats[interface_name].isup:
            for addr in interface_addresses:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    interfaces.append({
                        'name': interface_name,
                        'ip': addr.address,
                        'netmask': addr.netmask
                    })
    
    return interfaces

def choose_interface():
    """让用户选择网络接口"""
    interfaces = get_network_interfaces()
    
    if not interfaces:
        print("❌ 未找到可用的网络接口")
        return None
    
    print("\n可用的网络接口:")
    for i, interface in enumerate(interfaces):
        print(f"{i+1}. {interface['name']} - IP: {interface['ip']}")
    
    try:
        choice = int(input("\n请选择要监听的接口编号: ")) - 1
        if 0 <= choice < len(interfaces):
            return interfaces[choice]
        else:
            print("❌ 无效的选择")
            return None
    except ValueError:
        print("❌ 请输入有效的数字")
        return None

def enable_promiscuous_mode_improved(interface_ip):
    """改进的混杂模式设置"""
    # 检查管理员权限
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("错误: 需要以管理员权限运行此脚本")
        return False
    
    SIO_RCVALL = 0x98000001
    RCVALL_ON = ctypes.c_ulong(1)
    ws2_32 = ctypes.windll.ws2_32
    
    try:
        # 创建原始套接字
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        
        # 绑定到指定IP
        raw_socket.bind((interface_ip, 0))
        
        # 设置套接字选项
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # 启用混杂模式
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
            print(f"✅ 成功启用网卡混杂模式!")
            print(f"📡 正在监听: {interface_ip}")
            return raw_socket
        else:
            error_code = ws2_32.WSAGetLastError()
            print(f"❌ 启用混杂模式失败，错误代码: {error_code}")
            return None
            
    except Exception as e:
        print(f"❌ 错误: {e}")
        return None

def capture_packets(raw_socket, target_ip=None):
    """捕获数据包，特别关注特定IP"""
    print(f"\n🔍 开始捕获数据包...")
    if target_ip:
        print(f"🎯 特别关注与 {target_ip} 相关的通信")
    print("按 Ctrl+C 停止捕获")
    
    try:
        packet_count = 0
        while True:
            try:
                raw_socket.settimeout(1.0)
                packet, addr = raw_socket.recvfrom(65535)
                
                if packet:
                    packet_count += 1
                    
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
                        
                        # 只显示与目标IP相关的包或其他重要包
                        if (target_ip and (src_ip == target_ip or dst_ip == target_ip)) or packet_count <= 20:
                            print(f"\n📦 数据包 #{packet_count}, 长度: {len(packet)} 字节")
                            print(f"   📡 {src_ip} -> {dst_ip}")
                            print(f"   🔧 协议: {protocol}", end="")
                            
                            # 协议类型
                            if protocol == 1:
                                print(" (ICMP - Ping)", end="")
                                # 解析ICMP包
                                if len(packet) >= ip_header_length + 8:
                                    icmp_header = packet[ip_header_length:ip_header_length+8]
                                    icmph = struct.unpack('!BBH', icmp_header)
                                    icmp_type = icmph[0]
                                    icmp_code = icmph[1]
                                    print(f" - 类型: {icmp_type}, 代码: {icmp_code}")
                            elif protocol == 6:
                                print(" (TCP)", end="")
                            elif protocol == 17:
                                print(" (UDP)", end="")
                            else:
                                print("", end="")
                            print()
                            
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                print("\n⏹️  停止捕获")
                break
                
    except Exception as e:
        print(f"捕获数据包时出错: {e}")

def main_improved():
    """改进的主函数"""
    print("=" * 50)
    print("Windows 11 网卡混杂模式设置工具 (改进版)")
    print("=" * 50)
    
    # 选择网络接口
    interface = choose_interface()
    if not interface:
        return
    
    print(f"\n选择的接口: {interface['name']} - {interface['ip']}")
    
    # 获取要监控的目标IP
    target_ip = input("请输入要监控的目标IP (直接回车监控所有流量): ").strip()
    if not target_ip:
        target_ip = None
        print("🎯 将监控所有网络流量")
    else:
        print(f"🎯 将特别监控与 {target_ip} 相关的通信")
    
    # 启用混杂模式
    raw_socket = enable_promiscuous_mode_improved(interface['ip'])
    if raw_socket:
        try:
            # 开始捕获数据包
            capture_packets(raw_socket, target_ip)
        finally:
            raw_socket.close()
            print("🔒 套接字已关闭，恢复正常模式")

if __name__ == "__main__":
    try:
        main_improved()
        input("\n按 Enter 键退出...")
    except KeyboardInterrupt:
        print("\n\n⏹️  用户中断程序")
    except Exception as e:
        print(f"\n❌ 程序执行出错: {e}")