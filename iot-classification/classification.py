import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import re
import nmap
import time
import json
import requests
import logging
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor
from requests.auth import HTTPBasicAuth

from openai import OpenAI
from util import execute


class Scanner:
    def __init__(self):
        self.save_path = os.path.join(os.getcwd(), "result")

    def nmap_scan(self, ip, ports):
        scanner = nmap.PortScanner()
        scanner.scan(hosts=ip, arguments=f'-T4 -sV -p {ports}', timeout=60)
        if ip in scanner.all_hosts():
            for proto in scanner[ip].all_protocols():
                ports = scanner[ip][proto].keys()
                for port in sorted(ports):
                    port_info = scanner[ip][proto][port]
                    name = port_info.get('name', '')
                    product = port_info.get('product', '')
                    version = port_info.get('version', '')

                    log_info = f"ip: {ip} port: {port} state: {port_info['state']} name: {name} prd: {product} version: {version}"
                    logging.info(log_info)

    def nmap_scan_backend(self):
        """
        Using NMAP Scan mqtt backend port and running service
        :return:
        """
        base_scan_ports = [str(i) for i in self.mqtt_base_ports]

        with open(os.path.join(self.save_path, "MQTT/analysis/backend_ports.json"), "r") as f:
            bp = json.load(f)

        scan_results = {}
        scanned_ip = 0

        all_ips = []
        all_ports = []

        for ip, ports in bp.items():
            scan_ports = sorted(list(set(base_scan_ports + ports)))
            scan_ports = ",".join(scan_ports)
            all_ips.append(ip)
            all_ports.append(scan_ports)

        batch_nmap_ip = split_list_by_size(all_ips, 2000)
        batch_nmap_ports = split_list_by_size(all_ports, 2000)

        with ThreadPoolExecutor(max_workers=2000) as executor:
            for batch_index in range(len(batch_nmap_ip)):
                batch_index_ip = batch_nmap_ip[batch_index]
                batch_index_port = batch_nmap_ports[batch_index]

                for ip, port in zip(batch_index_ip, batch_index_port):
                    try:
                        executor.submit(self.nmap_scan, ip, port)

                    except Exception as e:
                        print(f"[NMAP] Scanning {ip} Fail: {e}")

                    finally:
                        scanned_ip += 1

                time.sleep(70)
                if scanned_ip % 4000 == 0:
                    print(f"[NMAP] Scanned {scanned_ip} done!")

        with open(os.path.join(self.save_path, "MQTT/nmap/nmap_scan_results.json"), 'w') as f:
            json.dump(scan_results, f, indent=4)

    def zmap_scan(self, ip_file, category: str):
        """
        For each port in mqtt_ports.txt, scanning each ip in mqtt_ips.txt
        :return:
        """

        all_scan_ips = os.path.join(self.save_path, "MQTT/analysis/mqtt_ips.txt")

        for port in mqtt_scan_ports:
            save_scan_files = os.path.join(self.save_path, f"MQTT/zmap/open-{port}.txt")
            if os.path.exists(save_scan_files):
                continue
            command = f"zmap -p {port} --probes=5 -B 100M --dedup-method=window -w {all_scan_ips} -o {save_scan_files}"
            execute(command)
            # zmap -p 9011 --probes=5 -B 100M -i eth0 --dedup-method=window --output-filter="" -o camera.txt 187.102.79.30

    def zgrab_scan_backend(self):
        """
        For each port in MQTT/zmap/open-{port}.txt,
        :return:
        """
        mqtt_scan_ports = read_list_from_file(os.path.join(self.save_path, "MQTT/analysis/mqtt_ports.txt"))

        for port in mqtt_scan_ports:
            output_file = os.path.join(self.save_path, f"MQTT/zgrab2/{port}-service.json")
            if os.path.exists(output_file):
                continue
            file_path = os.path.join(self.save_path, f"MQTT/zmap/open-{port}.txt")
            command = f"zgrab2 mqtt --port {port} --connect-timeout 10 --input-file {file_path} --output-file {output_file}"
            execute(command)

        # zgrab2 http --port 9011 --connect-timeout 10 --input-file camera_ip.txt --output-file camera_http.json


class LLMClassifier:
    def __init__(self, key, model):
        self.secret_key = key  # Replace your token
        self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", self.secret_key))
        self.device_type = ["web server", "router", "printer", "camera", "database", "light bulb", "switch"]
        self.initialize(model)

    def initialize(self, model):
        if "OPENAI_API_KEY" not in os.environ.keys():
            os.environ["OPENAI_API_KEY"] = self.secret_key

        if model == "deepseek":
            self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", self.secret_key),
                                 base_url="https://api.deepseek.com")
        else:
            self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", self.secret_key))

    def classification(self, ip: str, port: int, protocol: str, descriptions: dict):

        system_prompt = f"""
        The device type in your answer should be in [{', '.join(self.device_type)}].
        The format of your answer must be JSON and the following is an example:

        EXAMPLE JSON OUTPUT:
        {{
            "160.16.52.187": "database"
        }}
        """

        user_prompt = f"""
        The following is the response to the probe request targeting {ip}, port {port}, using the {protocol} protocol.
        {descriptions}
        Please help me determine the type of this device.

        """

        messages = [{"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}]

        response = self.client.chat.completions.create(
            model="deepseek-chat",
            messages=messages,
            response_format={
                'type': 'json_object'
            }
        )

        with open(f"result/{ip}.json", "w") as f:
            json.dump(response.choices[0].message.content, f, indent=4)

        return json.loads(response.choices[0].message.content)

    def cot_classification(self, ip: str, service: dict, protocol: str, fingerprint: dict):

        system_prompt = f"""
        You are an expert network security analyst specializing in IoT device identification.
        The device type in your answer should be in [{', '.join(self.device_type)}].
        The format of your answer must be JSON and the following is an example:

        EXAMPLE JSON OUTPUT:
        {{
            "160.16.52.187": "database"
        }}

        """
        user_prompt = f"""

            Your task is to identify and classify an IoT device based on the provided Nmap scan results and a zgrab2 scan fingerprint.
            Please follow the instructions below to classify devices with IP address {ip}.

            Step 1: #### The following are all open ports on the device and the services running on them scanned by Nmap.
            {service}
            Please confirm whether the device type belongs to one of [{', '.join(self.device_type)}].

            Step 2: #### The following are the zgrab2 fingerprint scan results for all ports running {protocol}.
            {fingerprint}
            Please identify the specific device type.

        """


if __name__ == "__main__":
    ds_key = "sk-7b3b9d4fbaac4deb8fa84b3fdd03c113"
    lm = LLMClassifier(ds_key, "deepseek")

    with open("camera_http.json", "r") as f:
        ch = json.load(f)

    lm.cot_classification("187.102.79.30", 9011, "http", ch)