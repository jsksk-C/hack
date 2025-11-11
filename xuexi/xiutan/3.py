from scapy.all import *
from scapy.arch.windows import get_windows_if_list
import socket
import requests
import concurrent.futures

def test_interface_connectivity(ip):
    """测试接口是否能访问网络"""
    try:
        # 创建一个socket并绑定到特定接口
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.bind((ip, 0))
        
        # 尝试访问公共DNS
        s.connect(('8.8.8.8', 53))
        s.send(b'test')
        s.close()
        return True
    except:
        return False

def select_interface():
    """显示所有网络接口并让用户选择"""
    print("正在获取网络接口列表...")
    interfaces = get_windows_if_list()
    
    if not interfaces:
        print("❌ 未找到任何网络接口！")
        return None
    
    print(f"\n找到 {len(interfaces)} 个网络接口:")
    print("=" * 60)
    
    valid_interfaces = []
    
    for index, iface in enumerate(interfaces):
        interface_name = iface.get('name', '未知')
        description = iface.get('description', '无描述')
        ips = iface.get('ips', [])
        ipv4_addresses = [ip for ip in ips if ':' not in ip and ip != '127.0.0.1']
        
        # 检查接口状态
        is_up = iface.get('isup', False)
        status = "✅ 已启用" if is_up else "❌ 未启用"
        
        print(f"[{index}] {description}")
        print(f"    接口: {interface_name}")
        print(f"    状态: {status}")
        
        if ipv4_addresses:
            print(f"    IP地址: {', '.join(ipv4_addresses)}")
            
            # 测试网络连接
            for ip in ipv4_addresses:
                if test_interface_connectivity(ip):
                    print(f"    网络测试: ✅ 可以访问互联网")
                    valid_interfaces.append((index, iface))
                    break
            else:
                print(f"    网络测试: ❌ 无法访问互联网")
        else:
            print(f"    IP地址: 无IP地址")
        
        print()
    
    print("=" * 60)
    
    if not valid_interfaces:
        print("❌ 没有找到可用的网络接口！")
        return None
    
    # 让用户选择接口
    while True:
        try:
            choice = input(f"请选择要使用的接口编号 (0-{len(interfaces)-1}): ")
            choice_num = int(choice)
            
            if 0 <= choice_num < len(interfaces):
                selected_iface = interfaces[choice_num]['name']
                description = interfaces[choice_num].get('description', '无描述')
                print(f"\n✅ 已选择接口: {description}")
                return selected_iface
            else:
                print(f"❌ 请输入 0 到 {len(interfaces)-1} 之间的数字")
        except ValueError:
            print("❌ 请输入有效的数字")
        except KeyboardInterrupt:
            print("\n👋 用户中断选择")
            exit(0)

def packet_callback(packet):
    """处理捕获的数据包"""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if packet.haslayer(TCP):
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"📦 {proto}: {src_ip}:{sport} -> {dst_ip}:{dport}")
        
        elif packet.haslayer(UDP):
            proto = "UDP" 
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"📦 {proto}: {src_ip}:{sport} -> {dst_ip}:{dport}")
        
        else:
            print(f"📦 IP: {src_ip} -> {dst_ip}")

def main():
    """主函数"""
    print("Scapy 网络嗅探工具 - 简化版")
    print("=" * 40)
    
    # 选择接口
    selected_interface = select_interface()
    
    if not selected_interface:
        print("无法找到合适的网络接口，程序退出。")
        return
    
    print(f"\n开始嗅探接口: {selected_interface}")
    print("按 Ctrl+C 停止嗅探")
    print("-" * 40)
    
    try:
        # 开始嗅探
        sniff(iface=selected_interface, prn=packet_callback, store=0)
        
    except PermissionError:
        print("\n❌ 权限不足！请以管理员身份运行此脚本。")
    except OSError as e:
        print(f"\n❌ 接口错误: {e}")
        print("请确保已安装Npcap驱动: https://nmap.org/npcap/")
    except KeyboardInterrupt:
        print("\n👋 停止嗅探")
    except Exception as e:
        print(f"\n❌ 错误: {e}")

if __name__ == "__main__":
    main()