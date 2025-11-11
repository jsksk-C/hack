"""HTML 导出器（最小实现）"""
from .base_exporter import BaseExporter

class HtmlExporter(BaseExporter):
    def export(self, items, path):
        with open(path, 'w', encoding='utf-8') as f:
            f.write('<!doctype html>\n<html><head><meta charset="utf-8"><title>Subdomains</title></head><body>\n')
            f.write('<h1>Discovered Subdomains</h1>\n<ul>\n')
            for it in items:
                f.write(f'<li>{it}</li>\n')
            f.write('</ul>\n</body></html>')
