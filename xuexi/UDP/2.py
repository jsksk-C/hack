import socket
import subprocess
import time
import sys

def check_port_usage(port):
    """检查指定端口是否被占用"""
    try:
        # 方法1: 尝试绑定端口
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            test_socket.bind(('0.0.0.0', port))
            test_socket.close()
            return False  # 端口可用
        except OSError:
            test_socket.close()
            return True   # 端口被占用
    except:
        return None

def check_with_netstat(port):
    """使用netstat检查端口状态"""
    try:
        # Windows netstat命令
        result = subprocess.run(
            ['netstat', '-an'], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        
        if f":{port} " in result.stdout:
            return True  # 端口被占用
        else:
            return False  # 端口可用
    except:
        return None

def test_proxy_lifecycle():
    """测试代理完整生命周期"""
    print("=== UDP代理生命周期测试 ===")
    
    # 测试端口
    test_port = 5353
    
    print(f"\n1. 检查端口 {test_port} 初始状态...")
    if check_port_usage(test_port):
        print(f"   [-] 端口 {test_port} 已被占用，请先释放")
        return False
    else:
        print(f"   [+] 端口 {test_port} 可用")
    
    print(f"\n2. 启动代理到端口 {test_port}...")
    try:
        # 这里您需要手动启动代理进行测试
        print("   请在另一个终端运行: python udp_proxy.py 5353 8.8.8.8 53")
        input("   启动后按回车继续...")
        
        # 检查端口是否被占用
        if check_port_usage(test_port):
            print(f"   [+] 代理正在运行，端口 {test_port} 被占用")
        else:
            print(f"   [-] 代理可能未正确启动，端口 {test_port} 仍可用")
            return False
    except Exception as e:
        print(f"   [-] 启动测试失败: {e}")
        return False
    
    print(f"\n3. 停止代理...")
    print("   请在代理终端按 Ctrl+C 停止代理")
    input("   停止后按回车继续...")
    
    # 等待一段时间让资源释放
    time.sleep(2)
    
    print(f"\n4. 验证端口释放...")
    port_still_used = check_port_usage(test_port)
    netstat_check = check_with_netstat(test_port)
    
    print(f"   端口绑定测试: {'仍被占用' if port_still_used else '已释放'}")
    print(f"   Netstat检查: {'仍被占用' if netstat_check else '已释放'}")
    
    if not port_still_used and not netstat_check:
        print(f"\n[✓] 测试通过! 端口 {test_port} 已完全释放")
        return True
    else:
        print(f"\n[✗] 测试失败! 端口 {test_port} 可能未被完全释放")
        print("    可能的原因:")
        print("    - 代理进程仍在运行")
        print("    - 操作系统端口释放延迟")
        print("    - 其他程序占用了该端口")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        # 快速检查模式
        port_to_check = int(sys.argv[2]) if len(sys.argv) > 2 else 5353
        if check_port_usage(port_to_check):
            print(f"端口 {port_to_check} 被占用")
        else:
            print(f"端口 {port_to_check} 可用")
    else:
        # 完整测试模式
        test_proxy_lifecycle()