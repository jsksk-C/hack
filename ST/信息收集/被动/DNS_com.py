import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import sys
import time
import random

def bing_search(site, pages):
    subdomains = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    
    session = requests.Session()
    session.headers.update(headers)
    
    print(f"[*] 开始在Bing中搜索 {site} 的子域名，共 {pages} 页...")
    
    for page in range(1, int(pages) + 1):
        print(f"[*] 正在搜索第 {page} 页...")
        
        # 构建Bing搜索URL
        start = (page - 1) * 10
        url = f"https://www.bing.com/search?q=site:{site}&first={start}"
        
        try:
            response = session.get(url, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # 查找搜索结果中的链接
            links = []
            
            # 方法1：查找包含链接的h2标签（Bing搜索结果的主要结构）
            h2_tags = soup.find_all('h2')
            for h2 in h2_tags:
                a_tag = h2.find('a')
                if a_tag and a_tag.get('href'):
                    links.append(a_tag['href'])
            
            # 方法2：直接查找所有包含域名的链接
            all_links = soup.find_all('a', href=True)
            for link in all_links:
                href = link['href']
                if site in href and href.startswith(('http://', 'https://')):
                    links.append(href)
            
            # 处理找到的链接，提取子域名
            for link in links:
                try:
                    parsed_url = urlparse(link)
                    domain = parsed_url.netloc
                    
                    # 过滤掉非目标域名的结果
                    if site in domain and domain not in subdomains:
                        subdomains.append(domain)
                        print(f"[+] 发现子域名: {domain}")
                except Exception as e:
                    continue
            
            # 随机延迟，避免请求过快
            time.sleep(random.uniform(1, 3))
            
        except requests.RequestException as e:
            print(f"[-] 第 {page} 页请求失败: {e}")
            continue
        except Exception as e:
            print(f"[-] 第 {page} 页解析失败: {e}")
            continue
    
    # 去重并排序
    subdomains = sorted(list(set(subdomains)))
    
    print(f"\n[*] 搜索完成！共发现 {len(subdomains)} 个子域名:")
    for subdomain in subdomains:
        print(f"    {subdomain}")
    
    # 保存结果到文件
    filename = f"{site}_subdomains.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        for subdomain in subdomains:
            f.write(subdomain + '\n')
    
    print(f"[*] 结果已保存到: {filename}")
    
    return subdomains

if __name__ == '__main__':
    if len(sys.argv) == 3:
        site = sys.argv[1]
        pages = sys.argv[2]
        
        # 验证输入
        if not site or not pages.isdigit():
            print("错误: 请提供有效的域名和页数")
            print("用法: python script.py baidu.com 10")
            sys.exit(1)
            
        # 确保域名格式正确
        if not site.startswith(('http://', 'https://')):
            site = site.replace('www.', '')  # 移除www前缀
        
        print(f"目标域名: {site}")
        print(f"搜索页数: {pages}")
        print("-" * 50)
        
        subdomains = bing_search(site, pages)
        
    else:
        print("用法: python bing_subdomain.py <域名> <页数>")
        print("示例: python bing_subdomain.py baidu.com 10")
        sys.exit(1)