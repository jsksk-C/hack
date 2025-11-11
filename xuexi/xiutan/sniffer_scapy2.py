from scapy.all import *
from scapy.arch.windows import get_windows_if_list

def simple_packet_callback(packet):
    """
    基础的回调函数，打印捕获数据包的摘要信息。
    """
    print(packet.summary())

def detailed_packet_callback(packet):
    """
    详细的回调函数，解析并显示数据包的关键信息。
    """
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        print(f"IP {ip_src} -> {ip_dst} ", end="")
        
        if packet.haslayer(TCP):
            print(f"TCP sport:{packet[TCP].sport} dport:{packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"UDP sport:{packet[UDP].sport} dport:{packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print("ICMP")
        else:
            print(f"Protocol: {packet[IP].proto}")
    else:
        print(packet.summary())
    print("-" * 50)

# 主程序
print("开始使用 WLAN 接口进行网络嗅探...")
print("请确保以管理员身份运行此脚本！")
print()

try:
    # 方法1：使用 WLAN 接口进行基础嗅探
    print("方法1: 基础嗅探（显示摘要信息）")
    sniff(iface="WLAN", prn=simple_packet_callback, count=10)
    
    # 方法2：使用 WLAN 接口进行详细嗅探
    print("\n方法2: 详细嗅探（解析协议信息）")
    sniff(iface="WLAN", prn=detailed_packet_callback, count=15)
    
except Exception as e:
    print(f"嗅探失败: {e}")
    print("\n可能的原因和解决方案:")
    print("1. 请确保以管理员身份运行此脚本")
    print("2. 确保已安装 Npcap (而非 WinPcap)")
    print("3. 检查 WLAN 接口名称是否正确")
    
    # 如果 WLAN 接口失败，列出所有可用接口
    print("\n可用的网络接口:")
    try:
        interfaces = get_windows_if_list()
        for i, iface in enumerate(interfaces):
            print(f"{i}: {iface['name']} - {iface['description']}")
    except:
        print("无法获取接口列表")