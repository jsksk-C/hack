from scapy.all import *
import time

def enhanced_packet_callback(packet):
    """
    增强的数据包回调函数，显示更友好的信息
    """
    timestamp = time.strftime("%H:%M:%S", time.localtime(packet.time))
    
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        # 确定协议类型
        protocol = "Other"
        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            
            # 解析TCP标志
            flags_str = ""
            if flags & 0x02: flags_str += "SYN "
            if flags & 0x10: flags_str += "ACK "
            if flags & 0x08: flags_str += "PSH "
            if flags & 0x01: flags_str += "FIN "
            if flags & 0x04: flags_str += "RST "
            
        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            flags_str = ""
        else:
            sport = dport = "N/A"
            flags_str = ""
        
        # 显示友好的端口名称
        def get_service_name(port, protocol):
            common_ports = {
                80: "HTTP", 443: "HTTPS", 53: "DNS", 25: "SMTP", 
                110: "POP3", 143: "IMAP", 22: "SSH", 21: "FTP"
            }
            return common_ports.get(port, str(port))
        
        src_service = get_service_name(sport, protocol)
        dst_service = get_service_name(dport, protocol)
        
        # 输出格式化信息
        direction = "→" if ip_src == "172.20.187.169" else "←"
        print(f"[{timestamp}] {direction} {protocol} {ip_src}:{src_service} > {ip_dst}:{dst_service} {flags_str.strip()}")
        
        # 显示数据包长度
        print(f"      Length: {len(packet)} bytes")
        
    else:
        # 非IP数据包
        print(f"[{timestamp}] {packet.summary()}")
    
    print("-" * 70)

# 主程序
print("增强版无线网络嗅探器 - 正在运行...")
print("接口: WLAN")
print("按 Ctrl+C 停止嗅探")
print("=" * 70)

try:
    # 持续嗅探，直到用户中断
    sniff(iface="WLAN", prn=enhanced_packet_callback, store=0)
except KeyboardInterrupt:
    print("\n嗅探已停止")
except Exception as e:
    print(f"错误: {e}")

"""1.过滤特定流量：

# 只捕获HTTP流量
sniff(iface="WLAN", filter="tcp port 80", prn=packet_callback)

# 只捕获DNS查询
sniff(iface="WLAN", filter="udp port 53", prn=packet_callback)


2.保存捕获的数据包：

packets = sniff(iface="WLAN", count=50)
wrpcap("captured.pcap", packets)
print("数据包已保存到 captured.pcap")


3.实时分析特定协议：

def http_analyzer(packet):
    if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
        if packet.haslayer(Raw):
            payload = str(packet[Raw].load)
            if "HTTP" in payload:
                print("HTTP流量 detected!")
                print(payload[:200])  # 显示前200个字符

sniff(iface="WLAN", prn=http_analyzer)

"""