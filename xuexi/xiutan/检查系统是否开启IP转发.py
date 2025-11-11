import platform
import subprocess
import re
import ctypes
import os

def is_admin():
    """检查是否具有管理员权限"""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.getuid() == 0
    except:
        return False

def get_current_ip_forwarding_state():
    """获取当前IP转发状态"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                'netsh interface ip show global', 
                shell=True, 
                capture_output=True, 
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            # 检查中英文输出
            if "启用" in result.stdout or "enabled" in result.stdout.lower():
                return True
            elif "禁用" in result.stdout or "disabled" in result.stdout.lower():
                return False
            else:
                print("❌ 无法解析IP转发状态")
                return None
                
        elif platform.system() == "Linux":
            try:
                with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                    return f.read().strip() == "1"
            except FileNotFoundError:
                # 如果文件不存在，使用sysctl检查
                result = subprocess.run(
                    'sysctl net.ipv4.ip_forward', 
                    shell=True, 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    return "1" in result.stdout
                return False
        else:
            print(f"❌ 不支持的操作系统: {platform.system()}")
            return None
            
    except Exception as e:
        print(f"❌ 获取IP转发状态时出错: {e}")
        return None

def enable_ip_forwarding(enable=True):
    """启用或禁用IP转发 - 跨平台版本"""
    try:
        status = "启用" if enable else "禁用"
        print(f"正在{status}IP转发...")
        
        if platform.system() == "Linux":
            value = "1" if enable else "0"
            # 方法1: 直接修改proc文件
            try:
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write(value)
            except PermissionError:
                print("❌ 需要root权限")
                return False
                
            # 方法2: 使用sysctl命令
            cmd = f"sysctl -w net.ipv4.ip_forward={value}"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            if result.returncode == 0:
                print(f"✅ Linux IP转发已{status}")
                return True
            else:
                print(f"❌ 设置IP转发失败")
                return False
                
        elif platform.system() == "Windows":
            # 使用netsh命令
            cmd = f'netsh interface ipv4 set global forwardenabled={1 if enable else 0}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            if result.returncode == 0:
                print(f"✅ Windows IP转发已{status}")
                return True
            else:
                print(f"❌ 设置IP转发失败，错误信息：{result.stderr}")
                return False
        else:
            print(f"❌ 不支持的操作系统: {platform.system()}")
            return False
            
    except Exception as e:
        print(f"❌ 设置IP转发状态时出错: {e}")
        return False

def display_current_status():
    """显示当前IP转发状态"""
    state = get_current_ip_forwarding_state()
    if state is None:
        print("❌ 无法确定当前IP转发状态")
        return
    
    status_text = "✅ 已启用" if state else "❌ 已禁用"
    print(f"\n当前IP转发状态: {status_text}")
    print(f"操作系统: {platform.system()} {platform.release()}")
    print("-" * 50)

def show_menu():
    """显示菜单选项"""
    print("\n" + "="*60)
    print("🛠️ IP转发管理工具")
    print("="*60)
    display_current_status()
    print("\n请选择操作:")
    print("1. ✅ 启用IP转发")
    print("2. ❌ 禁用IP转发") 
    print("3. 🔄 重新检查状态")
    print("4. 🚪 退出")
    print("-" * 30)

def main():
    """主函数"""
    print("🛠️ IP转发状态检测与配置工具")
    print(f"💻 系统: {platform.system()} {platform.release()}")
    
    # 检查管理员权限
    if not is_admin():
        print("❌ 请以管理员/root权限运行此程序!")
        if platform.system() == "Windows":
            print("💡 在Windows上: 右键点击命令提示符或PowerShell，选择'以管理员身份运行'")
        else:
            print("💡 在Linux上: 使用sudo命令运行")
        return
    
    print("✅ 管理员权限确认")
    
    while True:
        show_menu()
        
        try:
            choice = input("请输入选择 (1-4): ").strip()
            
            if choice == "1":
                if enable_ip_forwarding(True):
                    print("✅ IP转发启用成功!")
                else:
                    print("❌ IP转发启用失败!")
                    
            elif choice == "2":
                if enable_ip_forwarding(False):
                    print("✅ IP转发禁用成功!")
                else:
                    print("❌ IP转发禁用失败!")
                    
            elif choice == "3":
                display_current_status()
                
            elif choice == "4":
                print("👋 感谢使用，再见!")
                break
                
            else:
                print("❌ 无效选择，请输入1-4之间的数字")
                
            # 每次操作后等待一下
            input("\n按Enter键继续...")
            
        except KeyboardInterrupt:
            print("\n\n👋 用户中断，程序退出!")
            break
        except Exception as e:
            print(f"❌ 发生错误: {e}")

if __name__ == '__main__':
    main()