# 优化导入版本
import time
from scapy.sendrecv import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

def optimized_packet_callback(packet):
    """
    优化的数据包回调函数
    """
    timestamp = time.strftime("%H:%M:%S")
    
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        print(f"[{timestamp}] IP {src_ip} -> {dst_ip}", end="")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f" | TCP {tcp_layer.sport} → {tcp_layer.dport}", end="")
            
            # TCP标志位
            flags = tcp_layer.flags
            if flags:
                flag_names = []
                if flags & 0x02: flag_names.append("SYN")
                if flags & 0x10: flag_names.append("ACK") 
                if flags & 0x08: flag_names.append("PSH")
                if flags & 0x01: flag_names.append("FIN")
                if flags & 0x04: flag_names.append("RST")
                print(f" [{','.join(flag_names)}]", end="")
                
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f" | UDP {udp_layer.sport} → {udp_layer.dport}", end="")
            
        elif ICMP in packet:
            print(" | ICMP", end="")
            
        print(f" | Length: {len(packet)} bytes")

# 主程序
print("优化导入版本的网络嗅探器")
print("正在嗅探 WLAN 接口...")
print("-" * 60)

try:
    sniff(iface="WLAN", prn=optimized_packet_callback, count=20)
except Exception as e:
    print(f"错误: {e}")