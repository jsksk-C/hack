import os
import sys
import platform
import subprocess
import locale

def setup_encoding():
    """设置全局编码"""
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass
    if platform.system() == "Windows":
        try:
            os.system('chcp 65001 > nul 2>&1')
        except:
            pass

def safe_subprocess_run(cmd, shell=True):
    """安全的子进程执行函数"""
    try:
        result = subprocess.run(cmd, shell=shell, 
                              capture_output=True, text=True,
                              encoding='utf-8', errors='ignore')
        return result
    except UnicodeDecodeError:
        try:
            encoding = locale.getpreferredencoding()
            result = subprocess.run(cmd, shell=shell, 
                                  capture_output=True, text=True,
                                  encoding=encoding, errors='ignore')
            return result
        except Exception as e:
            print(f"子进程执行错误: {e}")
            return None
    except Exception as e:
        print(f"子进程执行错误: {e}")
        return None

def is_admin():
    """检查是否具有管理员权限"""
    try:
        if platform.system() == "Windows":
            from ctypes import windll
            return windll.shell32.IsUserAnAdmin()
        else:
            return os.getuid() == 0
    except:
        return False

def check_media_sense_status():
    """检查媒介感知状态"""
    print("🔍 正在检查媒介感知状态...")
    
    try:
        cmd = 'reg query "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v DisableDHCPMediaSense'
        result = safe_subprocess_run(cmd)
        
        if result and result.returncode == 0:
            if '0x1' in result.stdout:
                print("📊 当前状态: 媒介感知功能已禁用 (DisableDHCPMediaSense = 1)")
                return True  # 已禁用
            elif '0x0' in result.stdout:
                print("📊 当前状态: 媒介感知功能已启用 (DisableDHCPMediaSense = 0)")
                return False  # 已启用
            else:
                print("❓ 无法解析注册表值")
                return None
        else:
            print("📊 当前状态: 注册表项不存在，使用系统默认值 (媒介感知已启用)")
            return False  # 默认是启用的
    except Exception as e:
        print(f"❌ 检查媒介感知状态时出错: {e}")
        return None

def disable_media_sense():
    """禁用媒介感知功能"""
    print("🔄 正在禁用媒介感知功能...")
    
    try:
        cmd = 'reg add "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v DisableDHCPMediaSense /t REG_DWORD /d 1 /f'
        result = safe_subprocess_run(cmd)
        
        if result and result.returncode == 0:
            print("✅ 媒介感知功能已成功禁用")
            print("💡 注意: 此设置可能需要重启计算机或重启网络适配器才能生效")
            return True
        else:
            print("❌ 禁用媒介感知功能失败")
            if result:
                print(f"   错误信息: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ 禁用媒介感知功能时出错: {e}")
        return False

def enable_media_sense():
    """启用媒介感知功能"""
    print("🔄 正在启用媒介感知功能...")
    
    try:
        cmd = 'reg add "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v DisableDHCPMediaSense /t REG_DWORD /d 0 /f'
        result = safe_subprocess_run(cmd)
        
        if result and result.returncode == 0:
            print("✅ 媒介感知功能已成功启用")
            print("💡 注意: 此设置可能需要重启计算机或重启网络适配器才能生效")
            return True
        else:
            print("❌ 启用媒介感知功能失败")
            if result:
                print(f"   错误信息: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ 启用媒介感知功能时出错: {e}")
        return False

def delete_media_sense_registry():
    """删除媒介感知注册表项（恢复默认设置）"""
    print("🔄 正在删除媒介感知注册表项...")
    
    try:
        cmd = 'reg delete "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v DisableDHCPMediaSense /f'
        result = safe_subprocess_run(cmd)
        
        if result and result.returncode == 0:
            print("✅ 媒介感知注册表项已删除，恢复系统默认设置")
            print("💡 注意: 此设置可能需要重启计算机或重启网络适配器才能生效")
            return True
        else:
            # 如果删除失败，可能是因为键值不存在
            if "The system was unable to find the specified registry key or value" in result.stderr:
                print("✅ 媒介感知注册表项不存在，已经是默认设置")
                return True
            else:
                print("❌ 删除媒介感知注册表项失败")
                if result:
                    print(f"   错误信息: {result.stderr}")
                return False
    except Exception as e:
        print(f"❌ 删除媒介感知注册表项时出错: {e}")
        return False

def show_media_sense_info():
    """显示媒介感知功能的相关信息"""
    print("\n" + "="*60)
    print("📚 媒介感知功能说明")
    print("="*60)
    print("媒介感知 (Media Sense) 是Windows的网络检测功能:")
    print("")
    print("✅ 启用状态 (DisableDHCPMediaSense = 0):")
    print("   - 系统会自动检测网络连接状态")
    print("   - 当网线拔出时，系统会立即检测到并断开网络")
    print("   - 这是Windows的默认设置")
    print("")
    print("❌ 禁用状态 (DisableDHCPMediaSense = 1):")
    print("   - 系统不会自动检测网络连接状态变化")
    print("   - 网络连接状态变化时，IP地址不会立即释放")
    print("   - 在某些网络工具（如ARP欺骗）中可能需要禁用")
    print("")
    print("💡 应用场景:")
    print("   - 网络调试和工具开发时可能需要禁用")
    print("   - 虚拟化环境或特殊网络配置")
    print("   - 避免网络频繁重连")
    print("")
    print("⚠️  注意:")
    print("   - 修改此设置需要管理员权限")
    print("   - 修改后可能需要重启网络适配器或计算机")
    print("   - 普通用户建议保持默认启用状态")
    print("="*60)

def restart_network_adapter():
    """提供重启网络适配器的选项"""
    print("\n🔄 是否重启网络适配器使设置生效?")
    print("1. 重启所有网络适配器")
    print("2. 查看网络适配器列表")
    print("3. 跳过重启")
    
    try:
        choice = input("请选择 (默认3): ").strip() or "3"
        
        if choice == "1":
            print("🔄 正在重启所有网络适配器...")
            cmd = 'netsh interface set interface "Ethernet" admin=disable && timeout 3 && netsh interface set interface "Ethernet" admin=enable'
            result = safe_subprocess_run(cmd)
            if result and result.returncode == 0:
                print("✅ 网络适配器已重启")
            else:
                print("⚠️  网络适配器重启可能失败，建议手动重启")
        
        elif choice == "2":
            print("📋 网络适配器列表:")
            cmd = 'netsh interface show interface'
            result = safe_subprocess_run(cmd)
            if result:
                print(result.stdout)
            
            adapter_name = input("请输入要重启的适配器名称: ").strip()
            if adapter_name:
                cmd = f'netsh interface set interface "{adapter_name}" admin=disable && timeout 2 && netsh interface set interface "{adapter_name}" admin=enable'
                result = safe_subprocess_run(cmd)
                if result and result.returncode == 0:
                    print(f"✅ 适配器 {adapter_name} 已重启")
                else:
                    print(f"❌ 适配器 {adapter_name} 重启失败")
    
    except KeyboardInterrupt:
        print("\n⏹️  用户取消操作")

def main_menu():
    """主菜单"""
    while True:
        print("\n" + "="*60)
        print("🛠️  Windows媒介感知功能管理工具")
        print("="*60)
        print("1. 🔍 检查当前媒介感知状态")
        print("2. ❌ 禁用媒介感知功能")
        print("3. ✅ 启用媒介感知功能")
        print("4. 🗑️  删除设置（恢复默认）")
        print("5. 📚 显示功能说明")
        print("6. 🔄 重启网络适配器")
        print("7. 🚪 退出")
        print("="*60)
        
        try:
            choice = input("请选择操作 (1-7): ").strip()
            
            if choice == "1":
                current_status = check_media_sense_status()
                if current_status is not None:
                    if current_status:
                        print("🎯 建议: 媒介感知已禁用，适合网络工具使用")
                    else:
                        print("🎯 建议: 媒介感知已启用，这是Windows默认设置")
            
            elif choice == "2":
                if not is_admin():
                    print("❌ 需要管理员权限才能修改媒介感知设置!")
                    continue
                
                current_status = check_media_sense_status()
                if current_status:
                    print("ℹ️  媒介感知已经是禁用状态")
                else:
                    if disable_media_sense():
                        restart_network_adapter()
            
            elif choice == "3":
                if not is_admin():
                    print("❌ 需要管理员权限才能修改媒介感知设置!")
                    continue
                
                current_status = check_media_sense_status()
                if not current_status:
                    print("ℹ️  媒介感知已经是启用状态")
                else:
                    if enable_media_sense():
                        restart_network_adapter()
            
            elif choice == "4":
                if not is_admin():
                    print("❌ 需要管理员权限才能修改媒介感知设置!")
                    continue
                
                if delete_media_sense_registry():
                    restart_network_adapter()
            
            elif choice == "5":
                show_media_sense_info()
            
            elif choice == "6":
                if not is_admin():
                    print("❌ 需要管理员权限才能重启网络适配器!")
                    continue
                restart_network_adapter()
            
            elif choice == "7":
                print("👋 再见!")
                break
            
            else:
                print("❌ 无效选择，请重新输入")
        
        except KeyboardInterrupt:
            print("\n👋 再见!")
            break
        except Exception as e:
            print(f"❌ 发生错误: {e}")

def main():
    """主函数"""
    setup_encoding()
    
    print("🛠️  Windows媒介感知功能管理工具")
    print(f"💻 系统: {platform.system()} {platform.release()}")
    
    # 检查权限
    if not is_admin():
        print("❌ 警告: 当前不是管理员权限，部分功能可能无法使用!")
        print("💡 建议: 以管理员身份运行此程序以获得完整功能")
    
    # 显示当前状态
    check_media_sense_status()
    
    # 显示主菜单
    main_menu()

if __name__ == "__main__":
    main()