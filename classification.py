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
from util import *

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    filemode='a',
    filename=os.path.join(os.getcwd(), "initial.log")
)


class Scanner:
    def __init__(self):
        self.classify_result_path = os.path.join(os.getcwd(), "result")
        self.dataset_path = os.path.join(os.getcwd(), "dataset/v4")
        self.analysis_path = os.path.join(os.getcwd(), "analysis/v4")
        self.nmap_result_path = os.path.join(self.analysis_path, "nmap")
        self.zmap_result_path = os.path.join(self.analysis_path, "zmap")
        self.zgrab2_result_path = os.path.join(self.analysis_path, "zgrab2")

        self.http_iot_ports = [80, 443, 3000, 5000, 8000, 8080, 8888]
        # self.device_category = get_subdirectories_os(self.dataset_path)
        self.device_category = ["camera"]

    def acquire_device_ports(self):
        for dev_name in self.device_category:
            dev_files = list_files_in_folder(os.path.join(self.dataset_path, dev_name))

            dev_ip_ports = {}
            for dev_file in dev_files:
                with open(dev_file, "r") as f:
                    data = json.load(f)
                records = data["result"]["hits"]

                for record in records:
                    dev_ip_ports[record["ip"]] = []
                    for service in record["services"]:
                        if service["service_name"] in ["UNKNOWN", "HTTP", "HTTPS"]:
                            dev_ip_ports[record["ip"]].append(service["port"])

            with open(os.path.join(self.analysis_path, f"ip_port/{dev_name}.json"), "w") as f:
                json.dump(dev_ip_ports, f, indent=4)

    def nmap_single_scan(self, ip, ports):
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

    def nmap_scan(self):
        """
        Using NMAP Scan http devices port and running service
        :return:
        """
        base_scan_ports = [str(i) for i in self.http_iot_ports]

        for dev_name in self.device_category:

            change_log_file(os.path.join(self.nmap_result_path, f"{dev_name}.log"))

            with open(os.path.join(self.analysis_path, f"ip_port/{dev_name}.json"), "r") as f:
                ip_ports_file = json.load(f)

            scanned_ip = 0

            all_ips = []
            all_ports = []

            for ip, ports in ip_ports_file.items():
                ports = [str(port) for port in ports]
                scan_ports = sorted(list(set(base_scan_ports + ports)))
                scan_ports = ",".join(scan_ports)
                all_ips.append(ip)
                all_ports.append(scan_ports)

            batch_nmap_ip = split_list_by_size(all_ips, 50)
            batch_nmap_ports = split_list_by_size(all_ports, 50)

            with ThreadPoolExecutor(max_workers=50) as executor:
                for batch_index in range(len(batch_nmap_ip)):
                    batch_index_ip = batch_nmap_ip[batch_index]
                    batch_index_port = batch_nmap_ports[batch_index]

                    for ip, port in zip(batch_index_ip, batch_index_port):
                        try:
                            executor.submit(self.nmap_single_scan, ip, port)
                            print(f"[NMAP] Scanning {ip}")

                        except Exception as e:
                            print(f"[NMAP] Scanning {ip} Fail: {e}")

                        finally:
                            scanned_ip += 1

                    time.sleep(30)
                    # if scanned_ip % 4000 == 0:
                    #     print(f"[NMAP] Scanned {scanned_ip} done!")


            write_list_to_file(os.path.join(self.analysis_path, f"ips/{dev_name}.txt"), all_ips)
            write_list_to_file(os.path.join(self.analysis_path, f"ports/{dev_name}.txt"), all_ips)

    def zmap_scan(self):
        """
        For each port, scanning each ip in ips.txt
        :return:
        """
        for dev in self.device_category:

            port_path = os.path.join(self.analysis_path, f"ports/{dev}.txt")
            all_scan_ips = os.path.join(self.analysis_path, f"ips/{dev}.txt")
            all_ports = read_list_from_file(port_path)

            save_zmap_dir = os.path.join(self.zmap_result_path, f"{dev}")
            if not os.path.exists(save_zmap_dir):
                os.makedirs(save_zmap_dir)

            for port in all_ports:

                save_scan_files = os.path.join(self.zmap_result_path, f"{dev}/{port}.txt")

                if os.path.exists(save_scan_files):
                    continue
                command = f"zmap -p {port} --probes=5 -B 100M --dedup-method=window -w {all_scan_ips} -o {save_scan_files}"
                execute(command)
            # zmap -p 9011 --probes=5 -B 100M -i eth0 --dedup-method=window --output-filter="" -o camera.txt 187.102.79.30

    def zgrab_scan(self):
        """
        For each port in MQTT/zmap/open-{port}.txt,
        :return:
        """
        for dev in self.device_category:
            port_path = os.path.join(self.analysis_path, f"ports/{dev}.txt")
            all_scan_ips = os.path.join(self.analysis_path, f"ips/{dev}.txt")
            all_ports = read_list_from_file(port_path)

            save_zgrab_dir = os.path.join(self.zmap_result_path, f"{dev}")
            if not os.path.exists(save_zgrab_dir):
                os.makedirs(save_zgrab_dir)

            for port in all_ports:
                output_file = os.path.join(self.zgrab2_result_path, f"{dev}/{port}.json")
                if os.path.exists(output_file):
                    continue

                command = f"zgrab2 http --port {port} --connect-timeout 10 --input-file {all_scan_ips} --output-file {output_file}"
                execute(command)

        # zgrab2 http --port 9011 --connect-timeout 10 --input-file camera_ip.txt --output-file camera_http.json
        #


class LLMClassifier:
    def __init__(self, key, model):
        self.classify_result_path = os.path.join(os.getcwd(), "result")
        self.analysis_path = os.path.join(os.getcwd(), "analysis/v4")
        self.nmap_result_path = os.path.join(self.analysis_path, "nmap")
        self.zmap_result_path = os.path.join(self.analysis_path, "zmap")
        self.zgrab2_result_path = os.path.join(self.analysis_path, "zgrab2")

        self.secret_key = key  # Replace your token
        self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", self.secret_key))
        self.device_type = ["web server", "router", "printer", "camera", "database", "light bulb", "switch"]
        self.scanner = Scanner()
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
        """
        使用 LLM CoT 根据设备服务和端口开放情况，以及协议的指纹扫描情况，进行分类
        :param ip: 扫描的设备 ip
        :param service:
        :param protocol:
        :param fingerprint:
        :return:
        """
        system_prompt = f"""
        You are an expert network security analyst specializing in IoT device type classification.
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

        messages = [{"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}]

        response = self.client.chat.completions.create(
            model="deepseek-chat",
            messages=messages,
            response_format={
                'type': 'json_object'
            }
        )

        # save_result = {ip: response.choices[0].message.content}
        #
        # save_path = os.path.join(os.getcwd(), f"result/v4/{dev}")
        # if not os.path.exists(save_path):
        #     os.makedirs(save_path)
        #
        # save_file = os.path.join(save_path, "result.json")
        # if not os.path.exists(save_file):
        #     with open(save_file, "w") as f:
        #         json.dump(save_result, f, indent=4)
        #
        # else:
        #     with open(save_file, "r") as f:
        #         dev_type_result = json.load(f)
        #
        #     if ip not in dev_type_result:
        #         dev_type_result[ip] = response.choices[0].message.content

        return json.loads(response.choices[0].message.content)

    def fingerprint_integration(self, protocol: str):
        """
        分析各个设备ip的 zgrab2指纹信息，筛选加聚合
        :param protocol:
        :return:
        """
        for dev_name in self.device_type:
            ip_fingerprint = {}

            fingerprint_base_path = os.path.join(self.zgrab2_result_path, f"{dev_name}")
            if not os.path.exists(fingerprint_base_path):
                continue

            all_ports_fingerprints = list_files_in_folder(fingerprint_base_path)

            for port_fingerprint_path in all_ports_fingerprints:
                port = get_filename_without_extension(port_fingerprint_path)

                with open(port_fingerprint_path, "r") as f:
                    port_fingerprint = json.load(f)

                for ip, fingerprint in port_fingerprint.items():
                    if fingerprint["data"][protocol]["status"] != "success":
                        continue

                    if ip not in ip_fingerprint:
                        ip_fingerprint[ip] = {}
                    if port not in ip_fingerprint[ip]:
                        ip_fingerprint[ip][port] = {}
                        ip_fingerprint[ip][port] = fingerprint

            with open(os.path.join(fingerprint_base_path, "ip_fingerprint.json"), "w") as f:
                json.dump(ip_fingerprint, f, indent=4)

    def acquire_nmap_service(self, target_ip: str):
        """
        获取nmap扫描特定ip结果，包括各个ip的服务和开放端口
        :param target_ip: 目标ip
        :return:

        """
        log_pattern = re.compile(r"ip: ([\d\.]+) port: (\d+) state: (\w+) name: (\w+) prd: (\w+) version: (\w+)")

        service = {}

        for dev_name in self.device_type:
            log_path = os.path.join(self.nmap_result_path, f"{dev_name}.log")
            if not os.path.exists(log_path):
                continue

            with open(log_path, 'r') as f:
                for line in f:
                    match = log_pattern.search(line)
                    if match:
                        ip_address, port, state, name, prd, version = match.groups()
                        if ip_address == target_ip:
                            service[port] = {}
                            service[port]["state"] = state
                            service[port]["name"] = name
                            service[port]["prd"] = prd
                            service[port]["version"] = version
        return service

    def iot_classification(self, protocol: str):
        # Step 1: 对Censys数据进行扫描验证，拿到开放服务和端口
        self.scanner.acquire_device_ports()
        self.scanner.nmap_scan()
        self.scanner.zmap_scan()
        self.scanner.zgrab_scan()

        # Step 2: 根据各个设备开放的端口和服务信息 service，以及针对http协议的指纹扫描结果，使用LLM CoT进行分类
        for dev_name in self.device_type:

            service_file = os.path.join(self.nmap_result_path, f"{dev_name}.log")
            fingerprint_file_path = os.path.join(self.zgrab2_result_path, f"{dev_name}/ip_fingerprint.json")

            with open(fingerprint_file_path, "r") as f:
                fingerprints = json.load(f)

            save_path = os.path.join(os.getcwd(), f"result/v4/{dev_name}")
            if not os.path.exists(save_path):
                os.makedirs(save_path)

            save_file = os.path.join(save_path, "result.json")

            if not os.path.exists(save_file):
                with open(save_file, "w") as f:
                    json.dump({}, f, indent=4)

            with open(save_file, "r") as f:
                dev_type_result = json.load(f)

            # fingerprints: 每个ip对应一个zgrab2的 service
            for ip, ip_fingerprint in fingerprints.items():
                if ip not in dev_type_result:

                    service = self.acquire_nmap_service(ip)
                    classify_result = self.cot_classification(ip, service, protocol, ip_fingerprint)
                    if ip not in classify_result:
                        continue

                    dev_type_result[ip] = classify_result[ip]

            with open(save_file, "w") as f:
                json.dump(dev_type_result, f, indent=4)


if __name__ == "__main__":
    ds_key = ""
    lm = LLMClassifier(ds_key, "deepseek")
    lm.iot_classification("http")
