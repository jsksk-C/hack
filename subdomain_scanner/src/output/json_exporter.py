"""JSON 导出器（最小实现）"""
import json
from .base_exporter import BaseExporter

class JsonExporter(BaseExporter):
    def export(self, items, path):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(list(items), f, ensure_ascii=False, indent=2)
