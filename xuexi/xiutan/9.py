from scapy.all import *
import time
import threading

def create_test_packets():
    """创建测试数据包"""
    pop3_auth = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=12345, dport=110, flags="PA")/Raw(load="USER testuser\r\n")
    pop3_pass = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=12345, dport=110, flags="PA")/Raw(load="PASS testpass123\r\n")
    
    smtp_auth = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=12346, dport=25, flags="PA")/Raw(load="AUTH LOGIN\r\n")
    smtp_user = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=12346, dport=25, flags="PA")/Raw(load="dGVzdHVzZXI=\r\n")
    smtp_pass = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=12346, dport=25, flags="PA")/Raw(load="dGVzdHBhc3M=\r\n")
    
    return [pop3_auth, pop3_pass, smtp_auth, smtp_user, smtp_pass]

def packet_callback(packet):
    """数据包回调函数"""
    print(f"\n=== 捕获到数据包 ===")
    print(f"协议: {packet.name}")
    
    if packet.haslayer(IP):
        print(f"IP: {packet[IP].src} -> {packet[IP].dst}")
    
    if packet.haslayer(TCP):
        print(f"TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
        print(f"TCP Flags: {packet[TCP].flags}")
    
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        try:
            decoded = payload.decode('utf-8', errors='ignore')
            print(f"原始数据: {payload}")
            print(f"解码数据: {decoded.strip()}")
            
            # 检查是否有认证信息
            if any(keyword in decoded.lower() for keyword in ['user', 'pass', 'auth', 'login']):
                print("*** [!] 发现认证信息! ***")
        except Exception as e:
            print(f"解码错误: {e}")
    
    print("=" * 50)

def send_and_capture():
    """发送数据包并立即捕获"""
    print("开始发送测试数据包...")
    
    # 创建socket用于捕获
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind(('127.0.0.1', 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    test_packets = create_test_packets()
    
    for i, pkt in enumerate(test_packets):
        print(f"\n发送数据包 {i+1}/{len(test_packets)}")
        send(pkt, verbose=0)
        
        # 尝试捕获刚刚发送的数据包
        try:
            sock.settimeout(1.0)
            data, addr = sock.recvfrom(65535)
            packet = IP(data)
            packet_callback(packet)
        except socket.timeout:
            print("捕获超时，未收到数据包")
        except Exception as e:
            print(f"捕获错误: {e}")
        
        time.sleep(0.5)
    
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sock.close()

if __name__ == "__main__":
    send_and_capture()