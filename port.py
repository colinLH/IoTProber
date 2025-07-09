import os
import sys

sys.path.append(os.path.dirname(os.getcwd()))

import json
import subprocess
from util import *


class Scanner:
    def __init__(self):
        self.domain_path = os.path.join(os.getcwd(), "domain")
        self.dataset_path = os.path.join(os.getcwd(), "dataset")
        self.result_path = os.path.join(os.getcwd(), "result")
        self.rr_type = ["A", "AAAA", "MX", "CNAME", "NS", "TXT", "CAA", "RRSIG", "DNSKEY",
                        "DS", "NSEC", "NSEC3", "CDNSKEY", "CDS"]
        self.scan_ports = [80, 443, 1883, 5671, 5682, 5683, 5684, 5686, 8443, 8883, 9123, 9124]

    def all_domain_ip(self):
        with open(os.path.join(self.domain_path, "domain_rr.json"), "r") as f:
            domain_rr = json.load(f)

        domain_v4 = []
        domain_v6 = []

        for domain, rr in domain_rr.items():
            if "A" in rr.keys():
                for v4 in rr["A"]:
                    domain_v4.extend(v4)
            if "AAAA" in rr.keys():
                for v6 in rr["AAAA"]:
                    domain_v6.extend(v6)

        save_path = os.path.join(self.result_path, "domain_ip")

        domain_v4_2 = list(set(domain_v4))
        domain_v6_2 = list(set(domain_v6))

        write_list_to_file(os.path.join(save_path, "domain_v4.txt"), domain_v4_2)
        write_list_to_file(os.path.join(save_path, "domain_v6.txt"), domain_v6_2)

    def run_zmap(self, bandwidth: str, probe: int, dedup_method: str, ip_file: str, output_file: str):

        save_path = os.path.join(self.result_path, "domain_port")
        read_ip_path = os.path.join(self.result_path, "domain_ip")
        ip_file = os.path.join(read_ip_path, ip_file + ".txt")

        for port in self.scan_ports:
            o_file = os.path.join(save_path, output_file + f"-{port}.csv")
            command = f"zmap -p {port} --probes={probe} -B {bandwidth} --dedup-method={dedup_method} -w {ip_file} -o {o_file}"
            print(command)
            execute(command)

    def run_nmap(self, port: list, ip_file: str, output_file: str):
        save_path = os.path.join(self.result_path, "domain_nmap")
        read_ip_path = os.path.join(self.result_path, "domain_ip")
        ip_file = os.path.join(read_ip_path, ip_file + ".txt")
        o_file = os.path.join(save_path, output_file + ".nmap")

        ports = ",".join(port)
        command = f"nmap -sV -p {ports} -iL {ip_file} -oN {o_file}"
        execute(command)

    def run_zgrab2(self, port: str, timeout: int, ip_file: str, out_file: str):
        service_path = os.path.join(self.result_path, "service")
        read_ip_path = os.path.join(self.result_path, "domain_ip")
        input_file = os.path.join(read_ip_path, ip_file + ".txt")
        output_file = os.path.join(service_path, f"{out_file}-{port}.json")

        command = f"zgrab2 mqtt --port {port} --connect-timeout {timeout} --input-file {input_file} --output-file {output_file}"
        execute(command)


if __name__ == "__main__":

    zs = Scanner()
    zs.all_domain_ip()
    mqtt_ports = ["1883", "8883"]
    zs.run_zmap("100M", 2, "window", "domain_v4", "port")
    zs.run_nmap(mqtt_ports, "domain_v4", "mqtt_service")

    for port in mqtt_ports:
        zs.run_zgrab2(port, 10, "domain_v4", "mqtt_service")