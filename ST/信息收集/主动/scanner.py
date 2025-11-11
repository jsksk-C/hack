import requests
import sys
import time

def scan_sensitive_directories():
    """
    Web敏感目录探测工具
    """
    print("=" * 50)
    print("    Web敏感目录探测工具")
    print("=" * 50)
    
    # 设置请求头，模拟浏览器访问
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    # 获取用户输入
    try:
        target_url = input("请输入目标URL (例如: example.com): ").strip()
        if not target_url:
            print("错误：URL不能为空！")
            return
            
        # 确保URL格式正确
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
            
        dict_file = input("请输入字典文件路径 (直接回车使用默认php.txt): ").strip()
        if dict_file == "":
            dict_file = "php.txt"
            
    except KeyboardInterrupt:
        print("\n用户中断操作")
        return
    except Exception as e:
        print(f"输入错误: {e}")
        return
    
    # 读取字典文件
    url_list = []
    try:
        print(f"正在读取字典文件: {dict_file}")
        with open(dict_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()  # 移除首尾空白字符
                if line and not line.startswith('#'):  # 跳过空行和注释行
                    url_list.append(line)
        print(f"成功加载 {len(url_list)} 个测试路径")
        
    except FileNotFoundError:
        print(f"错误：字典文件 '{dict_file}' 不存在！")
        print("请确保字典文件存在于当前目录，或提供完整的文件路径")
        return
    except Exception as e:
        print(f"读取字典文件时出错: {e}")
        return
    
    # 开始扫描
    print(f"\n开始扫描目标: {target_url}")
    print("扫描结果:")
    print("-" * 60)
    
    found_count = 0
    start_time = time.time()
    
    for path in url_list:
        # 构建完整的URL
        full_url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
        
        try:
            # 发送HTTP请求
            response = requests.get(full_url, headers=headers, timeout=10, allow_redirects=False)
            
            # 只显示有意义的状态码
            if response.status_code in [200, 301, 302, 403]:
                print(f"[{response.status_code}] {full_url}")
                found_count += 1
                
        except requests.exceptions.ConnectionError:
            print(f"[连接失败] {full_url}")
        except requests.exceptions.Timeout:
            print(f"[请求超时] {full_url}")
        except requests.exceptions.RequestException as e:
            pass  # 静默处理其他请求异常
        except KeyboardInterrupt:
            print("\n用户中断扫描")
            break
    
    # 扫描完成统计
    end_time = time.time()
    scan_time = end_time - start_time
    
    print("-" * 60)
    print(f"扫描完成！")
    print(f"总共测试: {len(url_list)} 个路径")
    print(f"发现有效: {found_count} 个路径")
    print(f"扫描耗时: {scan_time:.2f} 秒")

def create_default_dict():
    """
    创建默认字典文件
    """
    default_paths = [
        "# Web敏感路径字典",
        "# 常见敏感文件和目录",
        "admin",
        "administrator",
        "login",
        "wp-admin",
        "phpmyadmin",
        "config",
        "backup",
        "database",
        "sql",
        "test",
        "debug",
        "api",
        "web",
        "www",
        "index.php",
        "admin.php",
        "config.php",
        "backup.sql",
        ".git",
        ".svn",
        ".env",
        "robots.txt"
    ]
    
    try:
        with open("php.txt", "w", encoding="utf-8") as f:
            for path in default_paths:
                f.write(path + "\n")
        print("已创建默认字典文件: php.txt")
    except Exception as e:
        print(f"创建字典文件失败: {e}")

if __name__ == "__main__":
    # 检查是否要创建默认字典
    if len(sys.argv) > 1 and sys.argv[1] == "--create-dict":
        create_default_dict()
        sys.exit(0)
    
    # 检查默认字典是否存在
    try:
        with open("php.txt", "r"):
            pass
    except FileNotFoundError:
        print("默认字典文件 'php.txt' 不存在！")
        create = input("是否创建默认字典文件？(y/n): ").lower()
        if create == 'y':
            create_default_dict()
    
    # 运行扫描工具
    scan_sensitive_directories()