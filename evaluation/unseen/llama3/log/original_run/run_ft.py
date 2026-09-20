import os, sys, runpy
os.environ.setdefault("HF_HOME", "/dev/shm/ft/hf")
os.environ.setdefault("HF_DATASETS_CACHE", "/dev/shm/ft/hf")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
sys.path.insert(0, "/home/nfs/iotprober")          # from util import ...
runpy.run_path("/dev/shm/ft/fine-tune.py", run_name="__main__")
