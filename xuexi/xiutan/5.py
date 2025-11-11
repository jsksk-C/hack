from scapy.all import *

def packet_callback(packet):
    print(packet.show())

def main():
    # 只捕获DNS流量（UDP端口53）
    sniff(iface="以太网", prn=packet_callback, count=1, filter="udp port 53")

if __name__ == "__main__":
    main()

"""from scapy.all import *
from scapy.arch.windows import get_windows_if_list

def packet_callback(packet):
    print(packet.show())

def main():
    # 获取所有网络接口
    interfaces = get_windows_if_list()
    
    # 显示可用的网络接口
    print("可用的网络接口:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface['name']} - {iface.get('description', 'No description')}")
    
    # 选择接口
    try:
        iface_index = int(input("请选择要使用的接口编号: "))
        selected_iface = interfaces[iface_index]['name']
        print(f"使用接口: {selected_iface}")
    except (ValueError, IndexError):
        print("无效选择，使用默认接口")
        selected_iface = None
    
    # 开始嗅探
    sniff(iface=selected_iface, prn=packet_callback, count=1)

if __name__ == "__main__":
    main()
"""