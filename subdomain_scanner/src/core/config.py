"""配置管理：从 YAML 加载默认配置并提供访问接口"""
import yaml
from pathlib import Path

class Config:
    def __init__(self, path: str = None):
        default = Path(__file__).parents[2] / 'config' / 'default_config.yaml'
        self.path = Path(path) if path else default
        self._data = {}
        self.load()

    def load(self):
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                self._data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            self._data = {}

    def get(self, key, default=None):
        return self._data.get(key, default)

    def as_dict(self):
        return dict(self._data)
