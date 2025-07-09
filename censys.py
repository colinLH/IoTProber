import re
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import json
import nmap
import certifi
import pip_system_certs.wrapt_requests
import requests
import logging
import ssl
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor
from requests.auth import HTTPBasicAuth

import paho.mqtt.client as mqtt

from util import *
from location import plot_wordmap, plot_wordmap2

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    filemode='a',
    filename=os.path.join(os.getcwd(), "dataset/Censys/MQTT/improve/tls_1.log")
)


def split_ip_port(str_list: list):
    ips = []
    ports = []
    for backend in str_list:
        ips.append(backend.split(":")[0])
        ports.append(backend.split(":")[1])

    return ips, ports


class MQTTConnector:
    def __init__(self, session_time: int = 30):
        self.username = None
        self.save_path = os.path.join(os.getcwd(), "connect")
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.session_time = session_time
        self.initialize()
        self.mid_topic_map = {}

    def initialize(self):
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_subscribe = self.on_subscribe
        self.client.on_unsubscribe = self.on_unsubscribe
        self.client.enable_logger()

    def set_client(self, client: mqtt.Client):
        self.client = client
        self.initialize()

    # Define Callback Function
    def on_connect(self, client, userdata, flags, reason_code, properties):
        logging.info(f"Backend {client._host}: Connected status {reason_code}")
        try:
            result1, mid1 = client.subscribe("$SYS/#")
            result2, mid2 = client.subscribe("#")
        except TimeoutError:
            logging.error(f"Backend {client._host}: Timeout error")

        try:
            self.mid_topic_map[mid1] = "$SYS/#"
            self.mid_topic_map[mid2] = "#"
        except UnicodeDecodeError:
            logging.error(f"Backend {client._host}: Unicode error")

    def on_message(self, client, userdata, msg):
        try:
            topic_payload = msg.topic + " " + str(msg.payload)
            logging.info(f"Backend {client._host}: Received Message: {topic_payload}")
        except UnicodeDecodeError:
            logging.error(f"Backend {client._host}: topic: {msg.topic} Unicode error")

    def on_subscribe(self, client, userdata, mid, reason_code_list, properties):
        topic = self.mid_topic_map.get(mid, "<unknown>")

        logging.info(f"Backend {client._host}: Topic {topic}: subscription return code {reason_code_list}")
        try:
            reason_code = reason_code_list[0]
            if reason_code.is_failure:
                logging.info(
                    f"Backend {client._host}: Topic {topic}: Broker reject the subscription {reason_code}")
            else:
                logging.info(
                    f"Backend {client._host}: Topic {topic}: Broker granted the following QoS {reason_code.value}")
        except IndexError:
            pass

    def on_unsubscribe(self, client, userdata, mid, reason_code_list, properties):
        # Be careful, the reason_code_list is only present in MQTTv5.
        # In MQTTv3 it will always be empty
        if len(reason_code_list) == 0 or not reason_code_list[0].is_failure:
            print("unsubscribe succeeded (if SUBACK is received in MQTTv3 it success)")
        else:
            print(f"Broker replied with failure: {reason_code_list[0]}")
        client.disconnect()

    def connect(self, host: str, port: int, keepalive: int = 30):

        try:
            self.client.connect(host, port, keepalive)
            self.client.loop_start()
            time.sleep(self.session_time)
        except TimeoutError:
            logging.error(f"Connect {host} exceed timeout!")
        except ConnectionRefusedError:
            logging.error(f"Connect {host} refused by remote backend!")
        except Exception as e:
            logging.error(f"Connect {host} raise error: {e}")
        finally:
            self.client.loop_stop()
            self.client.disconnect()


class CensysData:
    def __init__(self, uid, secret):
        self.save_path = os.path.join(os.getcwd(), "dataset/Censys")
        self.api_id = uid
        self.secret = secret
        self.support_url = {
            "Host": {
                "Search": "https://search.censys.io/api/v2/hosts/search",
                "Aggregation": "https://search.censys.io/api/v2/hosts/aggregate",
                "IP": "https://search.censys.io/api/v2/hosts/{ip}",
                "Events": "https://search.censys.io/api/v2/experimental/hosts/{ip}/events",
                "Names": "https://search.censys.io/api/v2/hosts/{ip}/names",
                "Certificates": "https://search.censys.io/api/v2/hosts/{ip}/certificates",
                "Comments": "https://search.censys.io/api/v2/hosts/{ip}/comments",
            }
        }

        self.mqtt_base_ports = [1883, 8883, 5678, 8355, 8356, 8884, 443, 1884]

        self.improve_category_non_tls = {
            "1": ["BRUTE FORCE", "Bad user name or password"],
            "2": ["RANDOM CLIENT ID", "Client identifier not valid"],
            "3": ["AUTHORIZATION PASS", "Not authorized"],
            "4": ["CHANGE PROTOCOL VERSION", "Unsupported protocol version"],
        }

        self.improve_category_tls = {
            "1": ["SET LOCAL ISSUER CA",
                  "raise error: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1007)"],
            "2": ["ENHANCED TLS SS CA IN CHAIN",
                  "raise error: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain (_ssl.c:1007)"],
            "3": ["ENHANCED TLS SS CA",
                  "raise error: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1007)"],
            "4": ["UPDATE CA",
                  "raise error: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1007)"],
            "5": ["CHANGE EE KEY",
                  "raise error: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: EE certificate key too weak (_ssl.c:1007)"],
            "6": ["CHANGE CA",
                  "raise error: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: invalid CA certificate (_ssl.c:1007)"],
            "7": ["CHANGE TLS VERSION", "raise error: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1007)"],
            "8": ["UPDATE TLS VERSION",
                  "raise error: [SSL: TLSV1_ALERT_INSUFFICIENT_SECURITY] tlsv1 alert insufficient security (_ssl.c:1007)"]
        }

        self.check_fine_grained_status = ["Unspecified error", "Server unavailable",
                                          "exceed timeout", "refused by remote backend",
                                          "raise error: [WinError 10054] \u8fdc\u7a0b\u4e3b\u673a\u5f3a\u8feb\u5173\u95ed\u4e86\u4e00\u4e2a\u73b0\u6709\u7684\u8fde\u63a5\u3002"]

        self.basic_query_fields = ["ip", "location.city", "location.province", "location.coordinates.latitude",
                                   "location.coordinates.longitude", "operating_system.version",
                                   "operating_system.edition"]

        self.whois_query_fields = ["whois.network.name", "whois.organization.name", "whois.organization.address"]

        self.dns_query_fields = ["dns.reverse_dns.names"]

        self.service_query_fields = ["services.transport_protocol", "services.service_name",
                                     "services.extended_service_name", "services.port"]

        self.tls_query_fields = ["services.tls.version_selected", "services.tls.cipher_selected",
                                 "services.tls.presented_chain.issuer_dn", "services.tls.presented_chain.subject_dn"]

        self.mqtt_query_fields = ["services.mqtt.connection_ack_return.return_value",
                                  "services.mqtt.subscription_ack_return.return_value"]

    def acquire_query_fields(self):
        if (len(self.basic_query_fields) + len(self.dns_query_fields) + len(self.whois_query_fields) +
                len(self.dns_query_fields) + len(self.service_query_fields) +
                len(self.tls_query_fields) + len(self.mqtt_query_fields) > 25):

            raise Exception("Judge query fields overflow")

        else:
            return (self.basic_query_fields + self.whois_query_fields + self.dns_query_fields +
                    self.service_query_fields + self.tls_query_fields + self.mqtt_query_fields)

    def acquire_mqtt_backends(self):
        page_index = 58

        basic_query = {
            "q": "services.service_name: MQTT",
            "per_page": 100,
            "virtual_hosts": "EXCLUDE",
            "sort": "RELEVANCE",
            "cursor": "eyJhbGciOiJFZERTQSJ9.eyJub25jZSI6IkRnenh0aUc3eG12SVh6bEpyR1QzRXlXZXIwSGNwYVczWkJlSUIxQUtMcnMiLCJwYWdlIjo1OSwicmV2ZXJzZWQiOmZhbHNlLCJzZWFyY2hfYWZ0ZXIiOls3LjQ1MzU0MSwxNzQ2NjYxNjI2NzcwLCIyMjIuMTU0LjI0MS4yMDMiLG51bGxdLCJzb3J0IjpbeyJfc2NvcmUiOnsib3JkZXIiOiJkZXNjIn19LHsibGFzdF91cGRhdGVkX2F0Ijp7Im1pc3NpbmciOiJfbGFzdCIsIm1vZGUiOiJtaW4iLCJvcmRlciI6ImRlc2MifX0seyJpcCI6eyJtaXNzaW5nIjoiX2xhc3QiLCJtb2RlIjoibWluIiwib3JkZXIiOiJhc2MifX0seyJuYW1lLl9fcmF3Ijp7Im1pc3NpbmciOiJfbGFzdCIsIm1vZGUiOiJtaW4iLCJvcmRlciI6ImFzYyJ9fV0sInZlcnNpb24iOjF9.ZOJaQYcySrsVguPnoefu3_UZZjNgCsudjPQfGMkkmqE5C76phSOb3X4giyUsvV2bGndS6r0p3I05G_cMFF4iCQ",
            "fields": self.acquire_query_fields()
        }

        first_query_success = False
        while not first_query_success:
            response = requests.post(
                self.support_url["Host"]["Search"],
                auth=HTTPBasicAuth(self.api_id, self.secret),
                headers={"Content-Type": "application/json", "accept": "application/json"},
                data=json.dumps(basic_query)
            )

            if response.status_code == 200:
                data = response.json()

                page_index += 1
                first_query_success = True

                with open(os.path.join(self.save_path, f"MQTT/mqtt_backends_page{page_index}.json"), "w") as f:
                    json.dump(data, f, indent=4)

                print(f"Page {page_index} data has been fetched!")
                logging.info(f"Page {page_index} data has been fetched!")
                time.sleep(1)

            else:
                print(f"Error: {response.status_code} - {response.text}")
                logging.error(f"Error: {response.status_code} - {response.text}")
                time.sleep(10)
                continue

        while data["result"]["links"]["next"] != "":

            basic_query["cursor"] = data["result"]["links"]["next"]

            response = requests.post(
                self.support_url["Host"]["Search"],
                auth=HTTPBasicAuth(self.api_id, self.secret),
                headers={"Content-Type": "application/json", "accept": "application/json"},
                data=json.dumps(basic_query)
            )

            if response.status_code == 200:
                data = response.json()

                page_index += 1

                with open(os.path.join(self.save_path, f"MQTT/mqtt_backends_page{page_index}.json"), "w") as f:
                    json.dump(data, f, indent=4)

                print(f"Page {page_index} data has been fetched!")
                logging.info(f"Page {page_index} data has been fetched!")
                time.sleep(1)

            else:
                print(f"Error: {response.status_code} - {response.text}")
                logging.error(f"Error: {response.status_code} - {response.text}")
                time.sleep(10)
                continue

    def backend_location_scatter(self, protocol: str, scan_day: str):

        backend_location = []
        data_path = os.path.join(self.save_path, protocol)

        location_file_path = os.path.join(data_path, "analysis/mqtt_backend_location.txt")
        json_path = os.path.join(data_path, "data")

        if os.path.exists(location_file_path):
            backend_location = read_tuple_list_from_file(location_file_path)
        else:
            all_jsons = list_files_in_folder(json_path)

            for json_file in all_jsons:
                if not check_extension(json_file, ".json"):
                    continue

                with open(json_file, "r") as f:
                    record = json.load(f)

                backends = record["result"]["hits"]
                for backend in backends:
                    backend_location.append((backend["location"]["coordinates"]["latitude"],
                                             backend["location"]["coordinates"]["longitude"]))

            write_list_to_file(os.path.join(data_path, "analysis/mqtt_backend_location.txt"), backend_location)

        plot_wordmap(backend_location, protocol, scan_day)

    def backend_location_intensity(self, protocol: str):
        """
        Analyze the strength of the backend geographical distribution
        :param protocol: protocol name
        :return: A location intensity map
        """
        data_path = os.path.join(self.save_path, f"{protocol}/analysis")

        location_file_path = os.path.join(data_path, "mqtt_backend_location.txt")
        backend_location = read_tuple_list_from_file(location_file_path)

        china_latitude = [3.86, 53.55]
        china_longitude = [73.66, 135.05]

        china_backend_location = []
        all_backend_location = []

        for backend in backend_location:
            backend_latitude = round(backend[0], 2)
            backend_longitude = round(backend[1], 2)
            record = [backend_longitude, backend_latitude]

            if china_latitude[0] <= backend_latitude <= china_latitude[1] and china_longitude[0] <= backend_longitude <= \
                    china_longitude[1]:

                record_in_list = False
                for idx, item in enumerate(china_backend_location):
                    if item[:2] == record:
                        china_backend_location[idx][2] += 1
                        record_in_list = True
                        break

                if not record_in_list:
                    record.append(1)
                    china_backend_location.append(record)

            record_in_list = False
            for idx, item in enumerate(all_backend_location):
                if item[:2] == record:
                    all_backend_location[idx][2] += 1
                    record_in_list = True
                    break

            if not record_in_list:
                record.append(1)
                all_backend_location.append(record)

        df_china = pd.DataFrame(china_backend_location, columns=["lon", "lat", "num"])
        df_china.insert(0, "index", range(len(df_china)))
        save_csv_name_china = os.path.join(data_path, "mqtt_backend_location(china).csv")
        location_map_china = os.path.join(data_path, "mqtt_backend_location(china).html")
        df_china.to_csv(save_csv_name_china, index=False)
        plot_wordmap2(save_csv_name_china, location_map_china)

        df = pd.DataFrame(all_backend_location, columns=["lon", "lat", "num"])
        df.insert(0, "index", range(len(df)))
        save_csv_name = os.path.join(data_path, "mqtt_backend_location.csv")
        location_map = os.path.join(data_path, "mqtt_backend_location.html")
        df.to_csv(save_csv_name, index=False)
        plot_wordmap2(save_csv_name, location_map)

    def mqtt_analysis(self, data_available: bool = True, backend_location_visualize: bool = False):

        if not data_available:
            self.acquire_mqtt_backends()

        data_path = os.path.join(self.save_path, "MQTT")
        json_path = os.path.join(data_path, "data")
        all_jsons = list_files_in_folder(json_path)
        save_path = os.path.join(data_path, "analysis")

        connection_status_distribution = {}
        subscription_status_distribution = {}

        service_port_distribution = {}
        other_service_port_distribution = {}

        whois_organization_names = {}
        whois_network_names = {}

        mqtt_backend_domain = []

        for json_file in all_jsons:
            if not check_extension(json_file, ".json"):
                continue

            with open(json_file, "r") as f:
                record = json.load(f)

            backends = record["result"]["hits"]
            for backend in backends:
                backend_service = backend["services"]
                for service in backend_service:

                    # Analysis Task 1: 'mqtt' record including connection status and subscription status
                    if "mqtt" in service.keys():
                        if "connection_ack_return" in service["mqtt"].keys():
                            connection_status = service["mqtt"]["connection_ack_return"]["return_value"]

                            if connection_status not in connection_status_distribution.keys():
                                connection_status_distribution[connection_status] = {"count": 1, "ip": [backend["ip"]]}
                            else:
                                connection_status_distribution[connection_status]["count"] += 1
                                connection_status_distribution[connection_status]["ip"].append(backend["ip"])

                        if "subscription_ack_return" in service["mqtt"].keys():
                            subscription_status = service["mqtt"]["subscription_ack_return"]["return_value"]
                            if subscription_status not in subscription_status_distribution.keys():
                                subscription_status_distribution[subscription_status] = {"count": 1,
                                                                                         "ip": [backend["ip"]]}
                            else:
                                subscription_status_distribution[subscription_status]["count"] += 1
                                subscription_status_distribution[subscription_status]["ip"].append(backend["ip"])

                    # Analysis Task 2: Other running service with corresponding open port in the MQTT backend

                    if "port" not in service.keys():
                        continue

                    if "extended_service_name" in service.keys():
                        if service["extended_service_name"] == "MQTT":
                            continue

                        other_service_port_key = service["extended_service_name"] + ":" + str(service["port"])
                        if other_service_port_key not in other_service_port_distribution.keys():
                            other_service_port_distribution[other_service_port_key] = {"count": 1}
                        else:
                            other_service_port_distribution[other_service_port_key]["count"] += 1

                    elif "service_name" in service.keys():
                        if service["service_name"] == "MQTT":
                            continue

                        other_service_port_key = service["service_name"] + ":" + str(service["port"])
                        if other_service_port_key not in other_service_port_distribution.keys():
                            other_service_port_distribution[other_service_port_key] = {"count": 1}
                        else:
                            other_service_port_distribution[other_service_port_key]["count"] += 1

                # Analysis Task 3: Count the ports where mqtt is running on all mqtt backends
                for match_service in backend["matched_services"]:
                    if "port" not in match_service.keys():
                        continue

                    if "extended_service_name" in match_service.keys():
                        service_port_key = match_service["extended_service_name"] + ":" + str(match_service["port"])
                        if service_port_key not in service_port_distribution.keys():
                            service_port_distribution[service_port_key] = {"count": 1, "ip": [backend["ip"]]}
                        else:
                            service_port_distribution[service_port_key]["count"] += 1
                            service_port_distribution[service_port_key]["ip"].append(backend["ip"])

                    elif "service_name" in match_service.keys():
                        service_port_key = match_service["service_name"] + ":" + str(match_service["port"])
                        if service_port_key not in service_port_distribution.keys():
                            service_port_distribution[service_port_key] = {"count": 1, "ip": [backend["ip"]]}
                        else:
                            service_port_distribution[service_port_key]["count"] += 1
                            service_port_distribution[service_port_key]["ip"].append(backend["ip"])

                # Analysis Task 4: Statistics of all whois information running on the backend
                if "whois" in backend.keys():
                    if "organization" in backend["whois"].keys():
                        if "name" in backend["whois"]["organization"].keys():
                            whois_organization_name = backend["whois"]["organization"]["name"]
                            if whois_organization_name in whois_organization_names.keys():
                                whois_organization_names[whois_organization_name]["count"] += 1
                            else:
                                whois_organization_names[whois_organization_name] = {"count": 1}

                    if "network" in backend["whois"].keys():
                        if "name" in backend["whois"]["network"].keys():
                            whois_network_name = backend["whois"]["network"]["name"]
                            if whois_network_name in whois_network_names.keys():
                                whois_network_names[whois_network_name]["count"] += 1
                            else:
                                whois_network_names[whois_network_name] = {"count": 1}

                if "dns" in backend.keys() and "reverse_dns" in backend["dns"].keys() and "names" in backend["dns"][
                    "reverse_dns"].keys():
                    mqtt_backend_domain.extend(backend["dns"]["reverse_dns"]["names"])

        mqtt_backend_domain = list(set(mqtt_backend_domain))
        write_list_to_file(os.path.join(save_path, "mqtt_backend_domain.txt"), mqtt_backend_domain)

        with open(os.path.join(save_path, "connection_status.json"), "w") as f:
            json.dump(connection_status_distribution, f, indent=4)

        with open(os.path.join(save_path, "subscription_status.json"), "w") as f2:
            json.dump(subscription_status_distribution, f2, indent=4)

        with open(os.path.join(save_path, "service_port.json"), "w") as f3:
            json.dump(service_port_distribution, f3, indent=4)

        with open(os.path.join(save_path, "other_services_ports.json"), "w") as f4:
            json.dump(other_service_port_distribution, f4, indent=4)

        with open(os.path.join(save_path, "whois_organizations.json"), "w") as f5:
            json.dump(whois_organization_names, f5, indent=4)

        with open(os.path.join(save_path, "whois_networks.json"), "w") as f6:
            json.dump(whois_network_names, f6, indent=4)

        # 绘制backend 运行MQTT的端口分布信息
        self.plot_mqtt_distribution("service_port", "MQTT open ports and backend numbers", "MQTT Port", 20)

        # 分析 MQTT backend支持TLS的情况
        tls_count, tls_distribution, tls_cs_distribution = self.analyze_mqtt_tls()

        print(f"Supported TLS MQTT backend number: {tls_count}")

        self.plot_mqtt_distribution("tls_version", "MQTT backend selected TLS version distribution",
                                    "MQTT TLS Selected Version", len(tls_distribution.keys()))

        self.plot_mqtt_distribution("tls_cs_distribution", "MQTT TLS cipher selection distribution",
                                    "MQTT TLS Selected Cipher", 7)

        # 分析 MQTT连接和订阅状态的分布情况
        self.plot_mqtt_distribution("connection_status", "MQTT backend connection status distribution",
                                    "MQTT Connection Status", len(connection_status_distribution.keys()))

        self.plot_mqtt_distribution("subscription_status", "MQTT backend subscription status distribution",
                                    "MQTT Subscription Status", len(subscription_status_distribution.keys()))

        # 分析 MQTT Backend上其他开放的服务和对应的端口
        self.plot_mqtt_distribution("other_services_ports", "Other Services Running on the MQTT Backend",
                                    "Other Running Services", 15)

        if backend_location_visualize:
            self.backend_location_intensity("MQTT")
            self.backend_location_scatter("MQTT", "2025-05-08")

    def analyze_mqtt_tls(self):
        data_path = os.path.join(self.save_path, "MQTT/data")
        all_jsons = list_files_in_folder(data_path)
        save_path = os.path.join(self.save_path, "MQTT/analysis")

        tls_count = 0
        tls_distribution = {}
        tls_cs_distribution = {}

        for json_file in all_jsons:
            if not check_extension(json_file, ".json"):
                continue

            with open(json_file, "r") as f:
                record = json.load(f)

            backends = record["result"]["hits"]
            for backend in backends:
                backend_service = backend["services"]
                for service in backend_service:
                    if "tls" in service.keys():
                        if "version_selected" in service["tls"].keys():
                            vs = service["tls"]["version_selected"]
                        else:
                            vs = None

                        if "cipher_selected" in service["tls"].keys():
                            cs = service["tls"]["cipher_selected"]
                        else:
                            cs = None

                        if "extended_service_name" in service.keys():
                            if service["extended_service_name"] == "MQTT":
                                tls_count += 1
                                if vs is not None:
                                    if vs not in tls_distribution.keys():
                                        tls_distribution[vs] = {"count": 1}
                                    else:
                                        tls_distribution[vs]["count"] += 1
                                if cs is not None:
                                    if cs not in tls_cs_distribution.keys():
                                        tls_cs_distribution[cs] = {"count": 1}
                                    else:
                                        tls_cs_distribution[cs]["count"] += 1
                                continue

                        if "service_name" in service.keys():
                            if service["service_name"] == "MQTT":
                                tls_count += 1
                                if vs is not None:
                                    if vs not in tls_distribution.keys():
                                        tls_distribution[vs] = {"count": 1}
                                    else:
                                        tls_distribution[vs]["count"] += 1
                                if cs is not None:
                                    if cs not in tls_cs_distribution.keys():
                                        tls_cs_distribution[cs] = {"count": 1}
                                    else:
                                        tls_cs_distribution[cs]["count"] += 1
                                continue

        with open(os.path.join(save_path, "tls_version.json"), "w") as f:
            json.dump(tls_distribution, f, indent=4)

        with open(os.path.join(save_path, "tls_cs_distribution.json"), "w") as f:
            json.dump(tls_cs_distribution, f, indent=4)

        return tls_count, tls_distribution, tls_cs_distribution

    def plot_mqtt_distribution(self, filename: str, title: str, x_label: str, data_range: int):
        with open(os.path.join(self.save_path, f"MQTT/analysis/{filename}.json"), "r") as f:
            sp = json.load(f)

        data = {}
        for port in sp.keys():
            data[port] = {"count": sp[port]["count"]}

        sorted_items = sorted(data.items(), key=lambda x: x[1]['count'], reverse=True)
        cs = [item[0] for item in sorted_items]
        counts = [item[1]['count'] for item in sorted_items]

        print(f"{filename} distribution length: {len(cs)}")

        plt.figure(figsize=(25, 6))
        bars = plt.bar(range(0, data_range), counts[:data_range], color='red')

        for bar, count in zip(bars, counts[:data_range]):
            plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                     str(count), ha='center', va='bottom', fontsize=12)

        plt.title(f"{title}", fontsize=14)
        plt.ylabel("Number of Backends")
        plt.xlabel(f"{x_label}")
        plt.xticks(range(0, data_range), cs[:data_range])

        # 显示图像
        plt.tight_layout()
        plt.show()

    def acquire_available_mqtt_backend(self):
        mqtt_backend_filter_non_tls = []
        mqtt_backend_filter_tls = []

        mqtt_backend_non_tls = []
        mqtt_backend_tls = []

        with open(os.path.join(self.save_path, "MQTT/analysis/service_port.json"), "r") as f:
            sp = json.load(f)

        with open(os.path.join(self.save_path, "MQTT/analysis/connection_status.json"), "r") as f1:
            cs = json.load(f1)

        connection_accepted_ip = cs["Connection Accepted"]["ip"]

        for sp_key, sp_value in sp.items():
            port = sp_key.split(":")[1]

            for ip in sp_value["ip"]:
                if port == "1883":
                    mqtt_backend_non_tls.append(f"{ip}:{port}")
                else:
                    mqtt_backend_tls.append(f"{ip}:{port}")

                if ip in connection_accepted_ip:
                    if port == "1883":
                        mqtt_backend_filter_non_tls.append(f"{ip}:{port}")
                    else:
                        mqtt_backend_filter_tls.append(f"{ip}:{port}")

        write_list_to_file(os.path.join(self.save_path, "MQTT/connect/filtered_tls_backend.txt"),
                           mqtt_backend_filter_tls)

        write_list_to_file(os.path.join(self.save_path, "MQTT/connect/filtered_non_tls_backend.txt"),
                           mqtt_backend_filter_non_tls)

        write_list_to_file(os.path.join(self.save_path, "MQTT/connect/all_tls_backend.txt"),
                           mqtt_backend_tls)

        write_list_to_file(os.path.join(self.save_path, "MQTT/connect/all_non_tls_backend.txt"),
                           mqtt_backend_non_tls)

    def mqtt_runtime_connect(self, batch_size: int, session_time: int):
        non_tls_backend_all = read_list_from_file(os.path.join(self.save_path, "MQTT/connect/all_non_tls_backend.txt"))
        tls_backend_all = read_list_from_file(os.path.join(self.save_path, "MQTT/connect/all_tls_backend.txt"))

        ips_tls, ports_tls = split_ip_port(tls_backend_all)
        ips_non_tls, ports_non_tls = split_ip_port(non_tls_backend_all)

        print(f"TLS IPs: {len(ips_tls)} / TLS Ports: {len(ports_tls)}")
        print(f"NON-TLS IPs: {len(ips_non_tls)} / NON-TLS Ports: {len(ports_non_tls)}")

        batch_non_tls_ips = split_list_by_size(ips_non_tls, batch_size)
        batch_non_tls_ports = split_list_by_size(ports_non_tls, batch_size)

        batch_tls_ips = split_list_by_size(ips_tls, batch_size)
        batch_tls_ports = split_list_by_size(ports_tls, batch_size)

        try_connect_backend = 0

        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            for batch_index in range(len(batch_non_tls_ips)):
                batch_index_ip = batch_non_tls_ips[batch_index]
                batch_index_port = batch_non_tls_ports[batch_index]

                for ip, port in zip(batch_index_ip, batch_index_port):

                    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                    mqtt_connector = MQTTConnector(session_time)
                    mqtt_connector.set_client(mqtt_client)

                    try:
                        executor.submit(mqtt_connector.connect, ip, int(port), session_time)
                    except TimeoutError:
                        logging.error(f"MQTT Connector failed to connect to {ip}:{port}")

                    try_connect_backend += 1

                print(f"Batch: {batch_index} - Non-TLS Connect Backend: {try_connect_backend}")

                # Wait until all backends in this batch is done
                time.sleep(session_time * 2)

            print(f"Total try connect non-tls MQTT backend: {try_connect_backend}")
            time.sleep(session_time * 2)

            for batch_index in range(len(batch_tls_ips)):
                batch_index_ip = batch_tls_ips[batch_index]
                batch_index_port = batch_tls_ports[batch_index]

                for ip, port in zip(batch_index_ip, batch_index_port):

                    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                    mqtt_client.tls_set()
                    mqtt_client.tls_insecure_set(True)

                    mqtt_connector = MQTTConnector(session_time)
                    mqtt_connector.set_client(mqtt_client)

                    try:
                        executor.submit(mqtt_connector.connect, ip, int(port), session_time)
                    except TimeoutError:
                        logging.error(f"MQTT Connector failed to connect to {ip}:{port}")

                    try_connect_backend += 1

                print(f"Batch: {batch_index} - TLS Connect Backend: {try_connect_backend}")

                # Wait until all backends in this batch is done
                time.sleep(session_time * 2)

            print(f"Total try connect tls MQTT backend: {try_connect_backend}")
            time.sleep(session_time * 2)

    def analyze_mqtt_log(self):
        base_path = os.path.join(self.save_path, "MQTT/connect")
        save_path = os.path.join(self.save_path, "MQTT/0520")

        with open(os.path.join(base_path, "connect_0520.log"), "rb") as f:
            lines = f.readlines()

        connect_status = {}
        subscribe_topic_status = {"$SYS/#": {}, "#": {}}
        all_topics = {}
        backend_topic = {}

        connect_pattern = r"Backend (\d{1,3}(?:\.\d{1,3}){3}): Connected status (.+)"
        connect_error_pattern = r'Connect\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(.*)'

        subscribe_pattern = r"Backend (\d{1,3}(?:\.\d{1,3}){3}): Topic (.*?): (.*)"
        message_pattern = r"Backend (\d{1,3}(?:\.\d{1,3}){3}): Received Message: (\S+)"

        for line in lines:

            line = decode_mixed_logs(line)
            if line == "Fail":
                continue

            # Task 1: Analyze connect status
            connect_result = re.search(connect_pattern, line)
            if connect_result is not None:
                ip = connect_result.group(1)
                connect_info = connect_result.group(2)
                if connect_info in connect_status.keys():
                    if ip not in connect_status[connect_info]:
                        connect_status[connect_info].append(ip)
                else:
                    connect_status[connect_info] = [ip]

            connect_error_result = re.search(connect_error_pattern, line)
            if connect_error_result is not None:
                ip = connect_error_result.group(1)
                connect_error_info = connect_error_result.group(2)
                if connect_error_info in connect_status.keys():
                    if ip not in connect_status[connect_error_info]:
                        connect_status[connect_error_info].append(ip)
                else:
                    connect_status[connect_error_info] = [ip]

            # Task 2: Analyze subscribe topic
            subscribe_topic_result = re.search(subscribe_pattern, line)
            if subscribe_topic_result is not None:
                ip = subscribe_topic_result.group(1)
                subscribe_topic = subscribe_topic_result.group(2)
                if subscribe_topic in subscribe_topic_status.keys():
                    topic_status = subscribe_topic_result.group(3)
                    if topic_status in subscribe_topic_status[subscribe_topic].keys():
                        subscribe_topic_status[subscribe_topic][topic_status].append(ip)
                    else:
                        subscribe_topic_status[subscribe_topic][topic_status] = [ip]

            # Task 3: Analyze topic category
            message_result = re.search(message_pattern, line)
            if message_result is not None:
                ip = message_result.group(1)
                topic = message_result.group(2)
                if topic not in all_topics.keys():
                    all_topics[topic] = {"count": 1}
                else:
                    all_topics[topic]["count"] += 1

                if ip not in backend_topic.keys():
                    backend_topic[ip] = [topic]
                else:
                    if topic not in backend_topic[ip]:
                        backend_topic[ip].append(topic)

        with open(os.path.join(save_path, "connect_status.json"), "w", encoding='utf-8') as f:
            json.dump(connect_status, f, indent=4)

        with open(os.path.join(save_path, "subscribe_topic_status.json"), "w", encoding='utf-8') as f:
            json.dump(subscribe_topic_status, f, indent=4)

        with open(os.path.join(save_path, "all_topics.json"), "w", encoding='utf-8') as f:
            json.dump(all_topics, f, indent=4)

        with open(os.path.join(save_path, "backend_topic.json"), "w", encoding='utf-8') as f:
            json.dump(backend_topic, f, indent=4)

        print(f"Connect status category count: {len(connect_status)}")

        len1 = len(subscribe_topic_status["$SYS/#"].keys())
        len2 = len(subscribe_topic_status["#"].keys())

        print(f"Subscribe topic $SYS/# category count: {len1}")
        print(f"Subscribe topic # category count: {len2}")

        print(f"All topics count: {len(all_topics.keys())}")

    def acquire_mqtt_ports(self):
        """
        Scan mqtt backend port and running service
        :return:
        """
        all_ips = []
        common_mqtt_ports = []
        backend_ports = {}

        with open(os.path.join(self.save_path, "MQTT/analysis/service_port.json"), "r", encoding='utf-8') as f:
            sp = json.load(f)

        for ip_port, value in sp.items():
            port = ip_port.split(":")[1]

            # Task 1: Acquire all ports for mqtt backend running the MQTT service
            if port not in common_mqtt_ports:
                common_mqtt_ports.append(port)

            for ip in value["ip"]:
                if ip not in all_ips:
                    all_ips.append(ip)

                # Task 2: Acquire running ports for each backend
                if ip not in backend_ports.keys():
                    backend_ports[ip] = [port]
                else:
                    if port not in backend_ports[ip]:
                        backend_ports[ip].append(port)

        print(f"Backend Number: {len(all_ips)}")
        print(f"Common Mqtt Ports: {len(common_mqtt_ports)}")

        write_list_to_file(os.path.join(self.save_path, "MQTT/analysis/mqtt_ports.txt"), common_mqtt_ports)
        write_list_to_file(os.path.join(self.save_path, "MQTT/analysis/mqtt_ips.txt"), all_ips)

        with open(os.path.join(self.save_path, "MQTT/analysis/backend_ports.json"), "w", encoding='utf-8') as f:
            json.dump(backend_ports, f, indent=4)

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

    def zmap_scan_backend(self):
        """
        For each port in mqtt_ports.txt, scanning each ip in mqtt_ips.txt
        :return:
        """
        mqtt_scan_ports = read_list_from_file(os.path.join(self.save_path, "MQTT/analysis/mqtt_ports.txt"))
        all_scan_ips = os.path.join(self.save_path, "MQTT/analysis/mqtt_ips.txt")

        for port in mqtt_scan_ports:
            save_scan_files = os.path.join(self.save_path, f"MQTT/zmap/open-{port}.txt")
            if os.path.exists(save_scan_files):
                continue
            command = f"zmap -p {port} -i eth0 --probes=5 -B 100M --dedup-method=window -w {all_scan_ips} -o {save_scan_files}"
            execute(command)

    def zgrab2_scan_backend(self):
        """
        For each port in MQTT/zmap/open-{port}.txt,
        :return:
        """
        mqtt_scan_ports = read_list_from_file(os.path.join(self.save_path, "MQTT/analysis/mqtt_ports.txt"))
        all_scan_ips = os.path.join(self.save_path, "MQTT/analysis/mqtt_ips.txt")

        for port in mqtt_scan_ports:
            output_file = os.path.join(self.save_path, f"MQTT/zgrab2/{port}-service.json")
            if os.path.exists(output_file):
                continue
            # file_path = os.path.join(self.save_path, f"MQTT/zmap/open-{port}.txt")
            command = f"zgrab2 mqtt --port {port} --connect-timeout 10 --input-file {all_scan_ips} --output-file {output_file}"
            execute(command)

    def improve_connect_nontls(self, category: str, session_time: int = 120):
        """
        根据不同和TLS不相关的连接失败案例，尝试提升连接成功率
        1. For connection status is bad username and password, try different combinations
        2. For connection status is client identifier not valid, try set random client ID
        3. For connection status is not authorized,
        :return:
        """
        if category == "1":
            username = read_list_from_file(os.path.join(self.save_path, "MQTT/connect/username.txt"))
            password = read_list_from_file(os.path.join(self.save_path, "MQTT/connect/password.txt"))
            test_case = []
            for usr in username:
                for pwd in password:
                    test_case.append((usr, pwd))

        with open(os.path.join(self.save_path, "MQTT/0520/connect_status.json"), "r") as f:
            cs = json.load(f)

        non_tls_backend_all = read_list_from_file(os.path.join(self.save_path, "MQTT/connect/all_non_tls_backend.txt"))
        tls_backend_all = read_list_from_file(os.path.join(self.save_path, "MQTT/connect/all_tls_backend.txt"))

        ips_tls, ports_tls = split_ip_port(tls_backend_all)
        ips_non_tls, ports_non_tls = split_ip_port(non_tls_backend_all)

        allowed_client = cs[self.improve_category_non_tls[category][1]]
        log_tag = self.improve_category_non_tls[category][0]

        try_non_tls_backend = 0
        try_tls_backend = 0

        # FIXME: 添加对ip_tls和ips_non_tls的batch分割，以及睡眠时间

        with ThreadPoolExecutor(max_workers=2000) as executor:

            # Step 1: Analyze the non-TLS backend
            for index in range(len(non_tls_backend_all)):
                ip = ips_non_tls[index]
                port = ports_non_tls[index]
                if ip not in allowed_client:
                    continue

                if category == "1":  # PASSWORD BRUTE
                    for tc in test_case:
                        mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                        mqtt_client.username_pw_set(tc[0], tc[1])

                        mqtt_connector = MQTTConnector(120)
                        mqtt_connector.set_client(mqtt_client)

                        try:
                            executor.submit(mqtt_connector.connect, ip, int(port), session_time)
                        except TimeoutError:
                            logging.error(f"MQTT Connector failed to connect to {ip}:{port}")
                        finally:
                            try_non_tls_backend += 1

                if try_non_tls_backend % 1000 == 0:
                    print(f"[{log_tag}] Tried Backend: {try_non_tls_backend}")

            # Step 2: Analyze the TLS backend
            for index2 in range(len(tls_backend_all)):
                ip = ips_tls[index2]
                port = ports_tls[index2]
                if ip not in allowed_client:
                    continue

                if category == "1":  # PASSWORD BRUTE
                    for tc in test_case:
                        mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                        mqtt_client.username_pw_set(tc[0], tc[1])
                        mqtt_client.tls_set()
                        mqtt_client.tls_insecure_set(True)

                        mqtt_connector = MQTTConnector(120)
                        mqtt_connector.set_client(mqtt_client)

                        try:
                            executor.submit(mqtt_connector.connect, ip, int(port), session_time)
                        except TimeoutError:
                            logging.error(f"MQTT Connector failed to connect to {ip}:{port}")
                        finally:
                            try_tls_backend += 1

                if (try_non_tls_backend + try_tls_backend) % 1000 == 0:
                    print(f"[{log_tag}] Tried Backend: {try_non_tls_backend + try_tls_backend}")

    def improve_connect_tls(self, category: str, session_time: int = 120, batch_size: int = 2000):
        """
        根据不同TLS相关的连接失败案例，尝试提升TLS配置
        1. For connection status is unable to get local issuer certificate, using certifi提供的证书

        :param category: 需要提高连接成功率的类型
        :param session_time: 连接会话时间
        :param batch_size: 并发线程数和batch大小
        :return:
        """

        with open(os.path.join(self.save_path, "MQTT/analysis/backend_ports.json"), "r") as f:
            bp = json.load(f)

        with open(os.path.join(self.save_path, "MQTT/0520/connect_status.json"), "r") as f:
            cs = json.load(f)

        log_tag = self.improve_category_tls[category][0]
        connection_status = self.improve_category_tls[category][1]
        need_improve_backends = cs[connection_status]

        print(f"[IMPROVE TLS {category}] Backend Number: {len(need_improve_backends)}")

        connect_ips = []
        connect_ports = []
        for ip in need_improve_backends:
            if ip in bp.keys():
                ports = bp[ip]
            else:
                continue

            for port in ports:
                connect_ips.append(ip)
                connect_ports.append(port)

        batch_connect_ips = split_list_by_size(connect_ips, batch_size)
        batch_connect_ports = split_list_by_size(connect_ports, batch_size)

        improved_backend_count = 0

        with ThreadPoolExecutor(max_workers=batch_size) as executor:

            for batch_index in range(len(batch_connect_ips)):
                improve_connect_ip = batch_connect_ips[batch_index]
                improve_connect_ports = batch_connect_ports[batch_index]

                for ip, port in zip(improve_connect_ip, improve_connect_ports):

                    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

                    if category == "1":
                        mqtt_client.tls_set()

                    elif category == "7":
                        mqtt_client.tls_set(tls_version=ssl.PROTOCOL_TLS)

                    mqtt_client.tls_insecure_set(True)  # 配置不验证服务器主机名
                    mqtt_connector = MQTTConnector(session_time)
                    mqtt_connector.set_client(mqtt_client)

                    try:
                        executor.submit(mqtt_connector.connect, ip, int(port), session_time)
                    except TimeoutError:
                        logging.error(f"MQTT Connector failed to connect to {ip}:{port}")
                    finally:
                        improved_backend_count += 1

                print(f"[{log_tag}] Batch Index: {batch_index} - Total Tried Backend: {improved_backend_count}")

                time.sleep(session_time)


if __name__ == "__main__":
    cs = CensysData("d3d39d60-883b-4625-9148-a8597bce0d55", "NK5gR5nohhDSU5muPdus2e29kgVQAqdj")
    # cs.mqtt_analysis()
    # cs.acquire_available_mqtt_backend()
    # cs.mqtt_runtime_connect(2000, 120)
    # cs.analyze_mqtt_log()
    # cs.acquire_mqtt_ports()
    # cs.nmap_scan_backend()
    # cs.zmap_scan_backend()
    # cs.zgrab2_scan_backend()
    # cs.improve_connect("1", 120)
    # cs.improve_connect_tls("1")
