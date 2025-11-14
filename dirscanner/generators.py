# -*- coding: utf-8 -*-
"""
生成器模块
"""

import json
import csv
from typing import List, Dict
from urllib.parse import urlparse

from .models import ScanResult
from .analyzers import ResultAnalyzer

class DynamicWordlistGenerator:
    """动态字典生成器"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.target_name = self._extract_target_name()
        self.common_dirs = self._load_common_directories()
        self.common_files = self._load_common_files()
    
    def _extract_target_name(self) -> str:
        """从URL提取目标名称"""
        parsed = urlparse(self.target_url)
        domain = parsed.netloc
        domain = domain.split(':')[0]
        
        parts = domain.split('.')
        if len(parts) >= 2:
            if parts[0] in ['www', 'api', 'app', 'test', 'dev', 'staging']:
                return parts[1] if len(parts) > 1 else parts[0]
            return parts[0]
        return domain
    
    def _load_common_directories(self) -> List[str]:
        """加载常见目录列表"""
        return [
            'admin', 'administrator', 'admincp', 'adminpanel', 'manager', 
            'management', 'dashboard', 'control', 'console', 'backend',
            'webadmin', 'cpanel', 'panel', 'login', 'logon', 'signin',
            'config', 'configuration', 'settings', 'setup', 'install',
            'installer', 'update', 'upgrade', 'etc', 'conf',
            'backup', 'backups', 'bak', 'old', 'archive', 'archives',
            'back', 'backup_old', 'database_backup', 'db_backup',
            'src', 'source', 'code', 'develop', 'development', 'dev',
            'build', 'dist', 'app', 'application', 'apps', 'web',
            'www', 'public', 'public_html', 'html', 'htdocs',
            'api', 'apis', 'rest', 'json', 'xml', 'soap', 'webservice',
            'assets', 'static', 'media', 'upload', 'uploads', 'files',
            'images', 'img', 'css', 'js', 'javascript', 'fonts',
            'bin', 'boot', 'lib', 'opt', 'proc', 'root', 'sbin', 'usr', 'var',
            'test', 'tests', 'testing', 'docs', 'document', 'doc', 'wiki',
            '.git', '.svn', '.hg', '.cvs',
            'wp-admin', 'wp-content', 'wp-includes', 'administrator',
            'sites', 'modules', 'themes', 'plugins', 'components'
        ]
    
    def _load_common_files(self) -> List[str]:
        """加载常见文件列表"""
        return [
            'config.php', 'config.json', 'config.xml', 'config.yml',
            'config.ini', 'settings.php', 'database.php', 'db.php',
            '.env', '.env.local', '.env.production',
            'backup.sql', 'backup.zip', 'backup.tar', 'backup.tar.gz',
            'dump.sql', 'database_dump.sql',
            'admin.php', 'administrator.php', 'login.php', 'panel.php',
            'index.php', 'index.html', 'default.html', 'home.html',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'security.txt', 'humans.txt', 'favicon.ico',
            'error.log', 'access.log', 'debug.log',
            '.gitignore', '.git/config', '.svn/entries',
            '.htaccess', 'web.config', 'httpd.conf'
        ]
    
    def generate_target_specific_words(self) -> List[str]:
        """生成目标特定的字典"""
        words = set()
        target_name = self.target_name.lower()
        
        if not target_name or target_name in ['localhost', '127.0.0.1']:
            return list(set(self.common_dirs + self.common_files))
        
        target_variants = [
            target_name,
            f"{target_name}-admin", f"{target_name}-panel", f"{target_name}-login",
            f"{target_name}-backup", f"{target_name}-test", f"{target_name}-dev",
            f"admin-{target_name}", f"backup-{target_name}", f"test-{target_name}",
            f"dev-{target_name}", f"staging-{target_name}", f"prod-{target_name}",
            f"{target_name}2023", f"{target_name}2024", f"{target_name}_backup",
            f"{target_name}_old", f"{target_name}_new", f"{target_name}_test"
        ]
        
        words.update(self.common_dirs)
        words.update(self.common_files)
        words.update(target_variants)
        
        file_variants = []
        extensions = ['.php', '.asp', '.aspx', '.jsp', '.html', '.txt', '.bak', '.old']
        
        for word in list(words):
            if not any(word.endswith(ext) for ext in extensions) and '.' not in word:
                for ext in extensions:
                    file_variants.append(f"{word}{ext}")
        
        words.update(file_variants)
        
        return list(words)

class ReportGenerator:
    """报告生成器"""
    
    def __init__(self):
        pass
    
    def generate_json_report(self, results: List[ScanResult], stats: Dict, output_file: str):
        """生成JSON格式报告"""
        analyzer = ResultAnalyzer()
        clusters = analyzer.cluster_results(results)
        
        report = {
            'scan_info': {
                'target': stats.get('target', ''),
                'start_time': stats.get('start_time', 0),
                'duration': stats.get('duration', 0),
                'total_requests': stats.get('requests_sent', 0),
                'failed_requests': stats.get('requests_failed', 0),
                'meaningful_responses': stats.get('meaningful_responses', 0),
                'requests_per_second': stats.get('requests_per_second', 0)
            },
            'results_by_risk': {},
            'all_results': [r.to_dict() for r in results]
        }
        
        for risk_level, risk_results in clusters.items():
            report['results_by_risk'][risk_level] = [r.to_dict() for r in risk_results]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report
    
    def generate_csv_report(self, results: List[ScanResult], output_file: str):
        """生成CSV格式报告"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Status', 'Content Length', 'Content Type', 
                           'Title', 'Redirect URL', 'Response Time', 'Risk Level'])
            
            for result in results:
                writer.writerow([
                    result.url, result.status, result.content_length, 
                    result.content_type, result.title, result.redirect_url,
                    result.response_time, result.risk_level
                ])
    
    def generate_html_report(self, results: List[ScanResult], stats: Dict, output_file: str):
        """生成HTML格式报告"""
        analyzer = ResultAnalyzer()
        clusters = analyzer.cluster_results(results)
        
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>目录扫描报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .critical { background-color: #ffebee; }
        .high { background-color: #fff8e1; }
        .medium { background-color: #e8f5e8; }
        .low { background-color: #e3f2fd; }
        .info { background-color: #f5f5f5; }
        .redirects { background-color: #e0f2f1; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .risk-count { display: inline-block; padding: 5px 10px; margin-right: 10px; border-radius: 3px; color: white; }
        .critical-count { background-color: #f44336; }
        .high-count { background-color: #ff9800; }
        .medium-count { background-color: #4caf50; }
        .low-count { background-color: #2196f3; }
        .info-count { background-color: #9e9e9e; }
        .redirects-count { background-color: #009688; }
    </style>
</head>
<body>
    <h1>目录扫描报告</h1>
    
    <div class="summary">
        <h2>扫描摘要</h2>
        <p><strong>目标URL:</strong> {target}</p>
        <p><strong>扫描时长:</strong> {duration:.2f} 秒</p>
        <p><strong>总请求数:</strong> {total_requests}</p>
        <p><strong>成功响应:</strong> {meaningful_responses}</p>
        <p><strong>请求速率:</strong> {requests_per_second:.1f} 请求/秒</p>
        
        <h3>按风险等级分类</h3>
        <div>
            <span class="risk-count critical-count">严重: {critical_count}</span>
            <span class="risk-count high-count">高风险: {high_count}</span>
            <span class="risk-count medium-count">中风险: {medium_count}</span>
            <span class="risk-count low-count">低风险: {low_count}</span>
            <span class="risk-count info-count">信息: {info_count}</span>
            <span class="risk-count redirects-count">重定向: {redirects_count}</span>
        </div>
    </div>
    
    {results_sections}
    
    <script>
        function sortTable(n) {{
            var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
            table = document.getElementById("resultsTable");
            switching = true;
            dir = "asc";
            while (switching) {{
                switching = false;
                rows = table.rows;
                for (i = 1; i < (rows.length - 1); i++) {{
                    shouldSwitch = false;
                    x = rows[i].getElementsByTagName("TD")[n];
                    y = rows[i + 1].getElementsByTagName("TD")[n];
                    if (dir == "asc") {{
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {{
                            shouldSwitch = true;
                            break;
                        }}
                    }} else if (dir == "desc") {{
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {{
                            shouldSwitch = true;
                            break;
                        }}
                    }}
                }}
                if (shouldSwitch) {{
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                }} else {{
                    if (switchcount == 0 && dir == "asc") {{
                        dir = "desc";
                        switching = true;
                    }}
                }}
            }}
        }}
    </script>
</body>
</html>
        """
        
        results_sections = ""
        for risk_level in ['critical', 'high', 'medium', 'low', 'info', 'redirects']:
            risk_results = clusters.get(risk_level, [])
            if not risk_results:
                continue
                
            level_name = {
                'critical': '严重',
                'high': '高风险',
                'medium': '中风险',
                'low': '低风险',
                'info': '信息',
                'redirects': '重定向'
            }[risk_level]
            
            results_sections += f"""
    <h2>{level_name} ({len(risk_results)} 个)</h2>
    <table id="resultsTable">
        <tr>
            <th onclick="sortTable(0)">URL</th>
            <th onclick="sortTable(1)">状态码</th>
            <th onclick="sortTable(2)">内容长度</th>
            <th onclick="sortTable(3)">内容类型</th>
            <th onclick="sortTable(4)">标题</th>
            <th onclick="sortTable(5)">响应时间(ms)</th>
        </tr>
"""
            
            for result in risk_results:
                results_sections += f"""
        <tr class="{risk_level}">
            <td><a href="{result.url}" target="_blank">{result.url}</a></td>
            <td>{result.status}</td>
            <td>{result.content_length}</td>
            <td>{result.content_type}</td>
            <td>{result.title}</td>
            <td>{result.response_time:.2f}</td>
        </tr>
"""
            
            results_sections += "\n    </table>\n"
        
        html_content = html_template.format(
            target=stats.get('target', ''),
            duration=stats.get('duration', 0),
            total_requests=stats.get('requests_sent', 0),
            meaningful_responses=stats.get('meaningful_responses', 0),
            requests_per_second=stats.get('requests_per_second', 0),
            critical_count=len(clusters.get('critical', [])),
            high_count=len(clusters.get('high', [])),
            medium_count=len(clusters.get('medium', [])),
            low_count=len(clusters.get('low', [])),
            info_count=len(clusters.get('info', [])),
            redirects_count=len(clusters.get('redirects', [])),
            results_sections=results_sections
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)