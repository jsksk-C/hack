import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import sys

def bing_search(site, pages):
    Subdomain = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip,deflate',
        'referer': "http://cn.bing.com/search?q=email+site%3abaidu.com&qs=n&sp=-1&pq=emailsite%3abaidu.com&first=2&FORM=PERE1"
    }
    
    for page_num in range(1, int(pages) + 1):
        url = f"https://cn.bing.com/search?q=site%3a{site}&go=Search&qs=ds&first={(page_num - 1) * 10}&FORM=PERE"
        
        try:
            conn = requests.session()
            # 先访问一次Bing主页获取cookies
            conn.get('http://cn.bing.com', headers=headers, timeout=8)
            # 搜索请求
            html = conn.get(url, headers=headers, timeout=8)
            soup = BeautifulSoup(html.content, 'html.parser')
            
            # 查找搜索结果中的链接
            job_bt = soup.findAll('h2')
            for job in job_bt:
                if job.a and job.a.get('href'):
                    link = job.a.get('href')
                    try:
                        domain = f"{urlparse(link).scheme}://{urlparse(link).netloc}"
                        if domain not in Subdomain:
                            Subdomain.append(domain)
                            print(domain)
                    except Exception as e:
                        print(f"解析链接错误: {link}, 错误: {e}")
                        continue
                        
        except requests.exceptions.RequestException as e:
            print(f"请求错误 (第{page_num}页): {e}")
            continue
        except Exception as e:
            print(f"处理第{page_num}页时发生错误: {e}")
            continue
    
    return Subdomain

if __name__ == '__main__':
    if len(sys.argv) == 3:
        site = sys.argv[1]
        page = sys.argv[2]
        print(f"正在搜索 {site} 的子域名，共 {page} 页...")
        Subdomain = bing_search(site, page)
        print(f"\n搜索完成，共找到 {len(Subdomain)} 个子域名")
    else:
        print(f"使用方法: {sys.argv[0]} baidu.com 10")
        sys.exit(-1)