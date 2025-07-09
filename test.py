import nmap
import json
import time
import os
from util import *

save_path = os.path.join(os.getcwd(), "dataset/Censys")

all_files = list_files_in_folder(os.path.join(save_path, "MQTT/zmap"))

total = 0
for file_name in all_files:
    ips = read_list_from_file(file_name)
    total += len(ips)

print(len(all_files))
print(total)