import ctypes
import sys
import os
import time

def is_admin():
    """检查当前是否具有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    """主程序逻辑"""
    print("程序正在以管理员身份运行！")
    print("可以执行需要高权限的操作...")
    
    # 这里可以放置你的实际代码
    # 例如：
    # 1. 网络嗅探
    # 2. 系统文件操作
    # 3. 注册表修改
    # 4. 服务管理
    
    # 示例：显示当前工作目录
    print(f"当前工作目录: {os.getcwd()}")
    
    # 示例：尝试访问需要高权限的资源
    try:
        # 尝试访问系统目录（需要管理员权限）
        system_dir = "C:\\Windows\\System32\\drivers\\etc"
        files = os.listdir(system_dir)
        print(f"可以访问系统目录，包含 {len(files)} 个文件/文件夹")
    except PermissionError as e:
        print(f"权限错误: {e}")
    
    # 保持程序运行一段时间以便查看输出
    print("程序将在10秒后退出...")
    time.sleep(10)

if __name__ == "__main__":
    if is_admin():
        # 已经是管理员权限，直接运行主程序
        main()
    else:
        # 请求管理员权限
        print("请求管理员权限...")
        
        # 重新以管理员权限运行当前脚本
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None,  # 父窗口句柄
                "runas",  # 操作：以管理员身份运行
                sys.executable,  # 可执行文件：Python解释器
                f'"{__file__}"',  # 参数：当前脚本文件
                None,  # 工作目录
                1  # 显示窗口
            )
        except Exception as e:
            print(f"请求管理员权限失败: {e}")
            print("请手动以管理员身份运行此脚本")
        
        # 当前进程退出
        sys.exit()