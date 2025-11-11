import requests
import sys
import time
import urllib3
from urllib.parse import urljoin

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def enhanced_scan():
    """
    增强版Web敏感目录探测工具
    """
    print("=" * 60)
    print("       增强版Web敏感目录探测工具")
    print("=" * 60)
    
    # 更真实的请求头
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    try:
        target_url = input("请输入目标URL (例如: http://testphp.vulnweb.com): ").strip()
        if not target_url:
            print("错误：URL不能为空！")
            return
            
        # 自动补全协议
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        # 验证目标是否可访问
        print("正在验证目标可访问性...")
        try:
            test_response = requests.get(target_url, headers=headers, timeout=10, verify=False)
            print(f"目标响应状态: {test_response.status_code}")
        except Exception as e:
            print(f"目标不可访问: {e}")
            return
            
        dict_file = input("请输入字典文件路径 (直接回车使用增强字典): ").strip()
        if dict_file == "":
            dict_file = "enhanced_dict.txt"
            create_enhanced_dict()  # 创建增强字典
            
    except KeyboardInterrupt:
        print("\n用户中断操作")
        return
    
    # 读取字典文件
    paths_to_scan = []
    try:
        print(f"正在读取字典文件: {dict_file}")
        with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    paths_to_scan.append(line)
        print(f"成功加载 {len(paths_to_scan)} 个测试路径")
        
    except FileNotFoundError:
        print(f"错误：字典文件 '{dict_file}' 不存在！")
        return
    
    # 开始扫描
    print(f"\n开始扫描目标: {target_url}")
    print("扫描结果:")
    print("-" * 80)
    
    found_paths = []
    start_time = time.time()
    
    for i, path in enumerate(paths_to_scan, 1):
        # 显示进度
        if i % 10 == 0:
            print(f"进度: {i}/{len(paths_to_scan)}")
        
        # 构建完整URL
        full_url = urljoin(target_url, path)
        
        try:
            response = requests.get(
                full_url, 
                headers=headers, 
                timeout=8, 
                verify=False,
                allow_redirects=True  # 允许重定向
            )
            
            # 扩展有意义的状态码
            interesting_codes = [200, 301, 302, 403, 401, 500]
            if response.status_code in interesting_codes:
                # 检查响应内容长度，过滤掉太小的页面（可能是错误页面）
                content_length = len(response.content)
                if content_length > 100:  # 只显示内容长度大于100字节的页面
                    status_desc = {
                        200: "存在",
                        301: "重定向",
                        302: "临时重定向", 
                        403: "禁止访问",
                        401: "需要认证",
                        500: "服务器错误"
                    }
                    print(f"[{response.status_code}] {status_desc.get(response.status_code, '未知')} - {full_url} (大小: {content_length} bytes)")
                    found_paths.append((full_url, response.status_code, content_length))
            
        except requests.exceptions.ConnectionError:
            print(f"[连接失败] {full_url}")
        except requests.exceptions.Timeout:
            print(f"[请求超时] {full_url}")
        except Exception as e:
            pass
    
    # 扫描完成统计
    end_time = time.time()
    scan_time = end_time - start_time
    
    print("-" * 80)
    print("扫描完成！详细结果:")
    print("-" * 80)
    
    if found_paths:
        for url, status, size in found_paths:
            print(f"[{status}] {url} (大小: {size} bytes)")
    else:
        print("未发现有效路径")
        print("建议:")
        print("1. 尝试其他目标网站")
        print("2. 使用更全面的字典文件")
        print("3. 检查网络连接")
    
    print("-" * 80)
    print(f"统计信息:")
    print(f"总共测试: {len(paths_to_scan)} 个路径")
    print(f"发现有效: {len(found_paths)} 个路径") 
    print(f"扫描耗时: {scan_time:.2f} 秒")
    print(f"平均速度: {len(paths_to_scan)/scan_time:.2f} 个/秒")

def create_enhanced_dict():
    """创建增强版字典文件"""
    enhanced_paths = [
        "# 增强版Web敏感路径字典",
        "# 常见管理后台",
        "admin", "administrator", "login", "manager", "admin/login", "admin.php",
        "wp-admin", "wp-login.php", "administrator/index.php", "user/login",
        "backend", "console", "dashboard", "control", "cp",
        
        "# 数据库管理",
        "phpmyadmin", "pma", "myadmin", "mysql", "db", "database", 
        "adminer", "dbadmin", "sql", "webdb", "db/db-admin.php",
        
        "# 配置文件",
        "config", "configuration", "config.php", "config.php.bak", 
        "config.json", ".env", "env", "settings.py", "config.xml",
        "web.config", "application.ini", "config.inc.php",
        
        "# 备份文件", 
        "backup", "backups", "bak", "old", "temp", "tmp",
        "database.sql", "backup.sql", "www.zip", "site.tar.gz",
        "backup.zip", "backup.tar", "dump.sql",
        
        "# 版本控制",
        ".git", ".svn", ".hg", ".bzr", "CVS", 
        ".git/config", ".svn/entries",
        
        "# 日志文件",
        "logs", "log", "error.log", "access.log", "debug.log",
        
        "# 测试文件",
        "test", "test.php", "info.php", "phpinfo.php", "debug", 
        "demo", "example", "samples",
        
        "# API接口",
        "api", "api/v1", "rest", "graphql", "swagger", "swagger-ui",
        "api-docs", "doc", "docs",
        
        "# 敏感文件",
        ".htaccess", "robots.txt", "crossdomain.xml", "sitemap.xml",
        ".DS_Store", "thumbs.db", "package.json", "composer.json",
        
        "# 上传目录",
        "upload", "uploads", "files", "images", "attachments",
        
        "# 安装文件",
        "install", "setup", "install.php", "setup.php",
        
        "# 其他常见路径",
        "cgi-bin", "web-inf", "includes", "templates", "themes",
        "plugins", "modules", "vendor", "lib", "src"
    ]
    
    try:
        with open("enhanced_dict.txt", "w", encoding="utf-8") as f:
            for path in enhanced_paths:
                f.write(path + "\n")
        print("已创建增强字典文件: enhanced_dict.txt")
    except Exception as e:
        print(f"创建字典文件失败: {e}")

if __name__ == "__main__":
    enhanced_scan()
