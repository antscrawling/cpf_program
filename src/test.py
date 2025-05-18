import os
import shutil
import importlib.util

SRC_DIR = os.path.dirname(os.path.abspath(__file__))

def copy_source_files():
    for fname in os.listdir(SRC_DIR):
        if fname.endswith(('.py', '.json', '.csv', '.xml')):
            if not fname.startswith('test_') and fname != os.path.basename(__file__):
                src = os.path.join(SRC_DIR, fname)
                dst = os.path.join(SRC_DIR, f"test_{fname}")
                shutil.copy2(src, dst)
                print(f"Copied {fname} to test_{fname}")

def run_all_methods(module_name, module_path):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for attr in dir(module):
        obj = getattr(module, attr)
        if callable(obj) and not attr.startswith("__"):
            try:
                print(f"Running {module_name}.{attr}()")
                obj()
            except Exception as e:
                print(f"Error running {attr}: {e}")

copy_source_files()

for fname in os.listdir(SRC_DIR):
    if fname.endswith('.py') and not fname.startswith('test_') and fname != os.path.basename(__file__):
        run_all_methods(fname[:-3], os.path.join(SRC_DIR, fname))
        