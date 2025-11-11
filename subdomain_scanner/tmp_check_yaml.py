import sys

print('PYTHON_EXE:', sys.executable)
try:
    import yaml
    print('YAML_AVAILABLE: True')
    print('YAML_VERSION:', getattr(yaml, '__version__', 'unknown'))
except Exception as e:
    print('YAML_AVAILABLE: False')
    print('YAML_IMPORT_ERROR:', e)
