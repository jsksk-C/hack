"""简单日志封装，后续可替换为结构化日志"""
import logging

def get_logger(name=__name__, level=logging.INFO):
    logger = logging.getLogger(name)
    if not logger.handlers:
        h = logging.StreamHandler()
        fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
        h.setFormatter(fmt)
        logger.addHandler(h)
    logger.setLevel(level)
    return logger
