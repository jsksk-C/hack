def demo_sniffer():
    """演示嗅探器效果"""
    test_data = [
        {"src": "192.168.1.100:12345", "dst": "192.168.1.200:110", "data": "USER testuser"},
        {"src": "192.168.1.100:12345", "dst": "192.168.1.200:110", "data": "PASS testpass123"},
        {"src": "192.168.1.100:12346", "dst": "192.168.1.200:25", "data": "AUTH LOGIN"},
        {"src": "192.168.1.100:12346", "dst": "192.168.1.200:25", "data": "dGVzdHVzZXI="},
        {"src": "192.168.1.100:12346", "dst": "192.168.1.200:25", "data": "dGVzdHBhc3M="}
    ]
    
    print("模拟邮件嗅探器捕获结果:")
    print("=" * 60)
    
    for packet in test_data:
        print(f"\n捕获到数据包: {packet['src']} -> {packet['dst']}")
        print(f"负载: {packet['data']}")
        
        if 'user' in packet['data'].lower() or 'pass' in packet['data'].lower():
            print("[!] *** 发现认证信息! ***")
            print(f"[!] 目标地址: {packet['dst'].split(':')[0]}")
            print(f"[!] 完整负载: {packet['data']}")
            print("-" * 50)

if __name__ == "__main__":
    demo_sniffer()
