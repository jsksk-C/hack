from scapy.all import *

def packet_callback(packet):
    print(packet.show())

def main():
    # 在Windows上，你可以直接使用接口名或让Scapy自动选择
    # 方法1: 自动选择默认接口
    #sniff(prn=packet_callback, count=1)
    
    # 方法2: 如果你知道接口名
     sniff(iface="以太网", prn=packet_callback, count=1)

if __name__ == "__main__":
    main()