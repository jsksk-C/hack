from scapy.all import *
import time
import threading
import signal
import sys
import argparse
from scapy.arch.windows import get_windows_if_list

# 全局变量，用于控制嗅探
sniffing = True
packet_count = 0

def signal_handler(sig, frame):
    """处理Ctrl+C信号，优雅地停止嗅探"""
    global sniffing
    print("\n正在停止嗅探...")
    sniffing = False

def packet_callback(packet):
    """数据包回调函数"""
    global packet_count
    packet_count += 1
    
    timestamp = time.strftime("%H:%M:%S", time.localtime(packet.time))
    
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        print(f"[{timestamp}] #{packet_count} IP {ip_src} -> {ip_dst}", end="")
        
        if packet.haslayer(TCP):
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
            
            print(f" | TCP {sport} → {dport} [{flags_str.strip()}]", end="")
            
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f" | UDP {sport} → {dport}", end="")
            
        elif packet.haslayer(ICMP):
            print(" | ICMP", end="")
            
        print(f" | Length: {len(packet)} bytes")
    else:
        print(f"[{timestamp}] #{packet_count} {packet.summary()}")

def start_sniffing(interface, timeout, filter_expr):
    """启动嗅探线程"""
    global sniffing, packet_count
    
    print(f"开始嗅探接口 {interface}，超时时间: {timeout}秒")
    if filter_expr:
        print(f"过滤器: {filter_expr}")
    print("按 Ctrl+C 提前停止嗅探")
    print("-" * 70)
    
    # 重置计数器
    packet_count = 0
    
    # 启动嗅探线程
    sniff_thread = threading.Thread(
        target=lambda: sniff(
            iface=interface,
            prn=packet_callback,
            store=0,
            stop_filter=lambda x: not sniffing,
            filter=filter_expr
        )
    )
    sniff_thread.daemon = True
    sniff_thread.start()
    
    # 等待指定时间或直到用户中断
    start_time = time.time()
    try:
        while time.time() - start_time < timeout and sniffing:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    
    # 停止嗅探
    sniffing = False
    time.sleep(0.5)  # 给嗅探线程一点时间完成
    
    print("-" * 70)
    print(f"嗅探结束，共捕获 {packet_count} 个数据包")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="可控制嗅探时间的网络嗅探器")
    parser.add_argument("-i", "--interface", default="WLAN", 
                        help="网络接口名称 (默认: WLAN)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="嗅探时间(秒) (默认: 10)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF过滤器表达式 (例如: 'tcp port 80')")
    
    args = parser.parse_args()
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    
    # 显示可用接口
    print("可用的网络接口:")
    interfaces = get_windows_if_list()
    for i, iface in enumerate(interfaces):
        print(f"  {iface['name']} - {iface['description']}")
    print()
    
    # 启动嗅探
    start_sniffing(args.interface, args.timeout, args.filter)

if __name__ == "__main__":
    main()


""".1 基本用法（默认10秒）：   python sniffer.py

2. 指定嗅探时间（例如30秒）:   python sniffer.py -t 30

3. 指定网络接口和嗅探时间：  python sniffer.py -i "WLAN" -t 15

4. 使用过滤器（例如只捕获HTTP流量）:    python sniffer.py -t 20 -f "tcp port 80"

5. 组合使用所有选项:   python sniffer.py -i "WLAN" -t 60 -f "udp port 53"
"""