from scapy.all import *
from scapy.arch.windows import get_windows_if_list

def packet_callback(packet):
    """
    处理并显示捕获到的数据包
    """
    packet.show()

def select_interface():
    """
    显示所有网络接口的详细信息，并让用户选择
    """
    print("正在获取网络接口信息...")
    interfaces = get_windows_if_list()
    
    print("\n" + "="*60)
    print("                   可用的网络接口")
    print("="*60)
    
    # 显示每个接口的详细信息
    for index, iface in enumerate(interfaces):
        print(f"\n[{index}] 接口名称: {iface['name']}")
        print(f"    描述: {iface.get('description', '无描述')}")
        
        # 显示IP地址信息
        ips = iface.get('ips', [])
        ipv4_addresses = [ip for ip in ips if ':' not in ip]  # 简单过滤IPv4地址
        ipv6_addresses = [ip for ip in ips if ':' in ip]     # IPv6地址
        
        if ipv4_addresses:
            print(f"    IPv4地址: {', '.join(ipv4_addresses)}")
        if ipv6_addresses:
            # 只显示前两个IPv6地址以避免输出过长
            print(f"    IPv6地址: {', '.join(ipv6_addresses[:2])}{'...' if len(ipv6_addresses) > 2 else ''}")
        
        # 显示MAC地址
        mac = iface.get('mac', '未知')
        print(f"    MAC地址: {mac}")
        
        # 显示接口状态信息
        status = "已连接" if iface.get('isup', False) else "未连接"
        print(f"    状态: {status}")
    
    print("\n" + "="*60)
    
    # 让用户选择接口
    while True:
        try:
            choice = input("请选择要使用的接口编号 (输入对应的数字): ")
            choice_num = int(choice)
            if 0 <= choice_num < len(interfaces):
                selected_iface = interfaces[choice_num]['name']
                print(f"\n✅ 已选择接口: {interfaces[choice_num]['name']}")
                print(f"   描述: {interfaces[choice_num].get('description', '无描述')}")
                return selected_iface
            else:
                print(f"❌ 请输入 0 到 {len(interfaces)-1} 之间的数字")
        except ValueError:
            print("❌ 请输入有效的数字")
        except KeyboardInterrupt:
            print("\n👋 用户中断选择")
            exit(0)

def main():
    """
    主函数
    """
    print("Scapy 网络嗅探工具 - Windows 11")
    print("请注意: 请以管理员身份运行此脚本以获得最佳效果")
    
    # 选择接口
    selected_interface = select_interface()
    
    print(f"\n开始在网络接口 '{selected_interface}' 上嗅探数据包...")
    print("按 Ctrl+C 停止嗅探")
    
    try:
        # 开始嗅探数据包
        sniff(iface=selected_interface, prn=packet_callback, count=5)
        
    except PermissionError:
        print("\n❌ 权限不足！请以管理员身份运行此脚本。")
    except OSError as e:
        print(f"\n❌ 接口错误: {e}")
        print("可能的原因:")
        print("  - 接口名称不正确")
        print("  - 接口不可用")
        print("  - 未安装WinPcap或Npcap驱动")
        print("\n💡 建议: 请安装Npcap (https://nmap.org/npcap/)")
    except KeyboardInterrupt:
        print("\n👋 用户停止嗅探")
    except Exception as e:
        print(f"\n❌ 发生未知错误: {e}")

if __name__ == "__main__":
    main()