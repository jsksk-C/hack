from scapy.all import *

def packet_callback(packet):
    print(f"捕获到数据包: {packet.summary()}")
    if packet.haslayer(TCP):
        print(f"TCP 源端口: {packet[TCP].sport}, 目标端口: {packet[TCP].dport}")

def main():
    print("测试网络中的TCP流量...")
    # 先捕获一些TCP流量看看有什么端口
    sniff(iface="以太网", prn=packet_callback, count=10, filter="tcp", timeout=30)

if __name__ == "__main__":
    main()
from scapy.all import *

# 查看可用的网络接口
print("可用的网络接口:")
print(conf.ifaces)

# 或者使用以下命令查看
# print(get_windows_if_list())


