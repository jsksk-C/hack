from scapy.all import *

def simple_packet_callback(packet):
    print(packet.summary())

# 尝试使用接口名“WLAN”进行嗅探
try:
    print("开始嗅探无线网络流量（接口：WLAN）...")
    sniff(iface="WLAN", prn=simple_packet_callback, count=10)
except Exception as e:
    print(f"使用接口WLAN失败: {e}")
    print("尝试自动选择接口...")
    try:
        sniff(prn=simple_packet_callback, count=10)
    except Exception as e2:
        print(f"自动选择接口也失败: {e2}")