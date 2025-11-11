from scapy.all import *

def packet_callback(packet):
    print(packet.show())

def main():
    # 直接指定接口名
    sniff(iface="WLAN", prn=packet_callback, count=1)

if __name__ == "__main__":
    main()