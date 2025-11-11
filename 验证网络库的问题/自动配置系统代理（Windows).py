import winreg
import ctypes
import sys

def set_system_proxy(enable=True, proxy_server="127.0.0.1:8080"):
    """配置Windows系统代理"""
    
    try:
        # 打开注册表
        reg = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
        key = winreg.OpenKey(reg, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE)
        
        if enable:
            # 启用代理
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
            print("✅ 系统代理已启用")
        else:
            # 禁用代理
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            print("✅ 系统代理已禁用")
        
        winreg.CloseKey(key)
        winreg.CloseKey(reg)
        
        # 通知系统设置已更改
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        internet_set_option(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
        
        return True
        
    except Exception as e:
        print(f"❌ 配置系统代理失败: {e}")
        return False

# 使用示例
if __name__ == "__main__":
    if set_system_proxy(enable=True):
        print("请在Edge浏览器中访问 http://httpbin.org/html 测试注入效果")
        input("按Enter键禁用代理...")
        set_system_proxy(enable=False)