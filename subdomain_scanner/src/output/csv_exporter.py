"""CSV 导出器（最小实现）"""
import csv
from .base_exporter import BaseExporter

class CsvExporter(BaseExporter):
    def export(self, items, path):
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["subdomain"])  # header
            for item in items:
                writer.writerow([item])
