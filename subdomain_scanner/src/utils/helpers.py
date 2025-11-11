"""辅助函数：加载字典文件等小工具"""
from pathlib import Path
from typing import List

def load_wordlist(path: str) -> List[str]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open('r', encoding='utf-8') as f:
        return [l.strip() for l in f if l.strip()]
