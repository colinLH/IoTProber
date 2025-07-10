import re
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import json
import logging
import requests
from requests.auth import HTTPBasicAuth

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    filemode='a',
    filename=os.path.join(os.getcwd(), "dataset/Censys/dataset/data.log")
)


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
                len(self.tls_query_fields) > 25):
            raise Exception("Judge query fields overflow")

        else:
            return (self.basic_query_fields + self.whois_query_fields + self.dns_query_fields +
                    self.service_query_fields + self.tls_query_fields)

    def acquire_mqtt_backends(self, device_label: str, version: str):
        page_index = 0

        if version == "v4":
            basic_query = {
                "q": f"labels = {device_label}",
                "per_page": 100,
                "virtual_hosts": "EXCLUDE",
                "sort": "RELEVANCE",
                "fields": self.acquire_query_fields()
            }
        else:
            basic_query = {
                "q": f"(labels: ipv6) and labels = {device_label}",
                "per_page": 100,
                "virtual_hosts": "EXCLUDE",
                "sort": "RELEVANCE",
                "fields": self.acquire_query_fields()
            }

        base_dir = version
        first_query_success = False

        fail_time = 0
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

                with open(os.path.join(self.save_path, f"dataset/{base_dir}/{device_label}/page{page_index}.json"), "w") as f:
                    json.dump(data, f, indent=4)

                print(f"Page {page_index} data has been fetched!")
                logging.info(f"Page {page_index} data has been fetched!")
                time.sleep(1)

            else:
                fail_time += 1
                if fail_time > 1:
                    return
                print(f"Error: {response.status_code} - {response.text}")
                logging.error(f"Error: {response.status_code} - {response.text}")
                time.sleep(10)
                continue

        fail_time = 0
        while data["result"]["links"]["next"] != "" and page_index < 5:

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

                with open(os.path.join(self.save_path, f"dataset/{base_dir}/{device_label}/page{page_index}.json"), "w") as f:
                    json.dump(data, f, indent=4)

                print(f"Page {page_index} data has been fetched!")
                logging.info(f"Page {page_index} data has been fetched!")
                time.sleep(1)

            else:
                fail_time += 1
                if fail_time > 1:
                    return
                print(f"Error: {response.status_code} - {response.text}")
                logging.error(f"Error: {response.status_code} - {response.text}")
                time.sleep(10)
                continue


if __name__ == "__main__":
    cs = CensysData("d3d39d60-883b-4625-9148-a8597bce0d55", "NK5gR5nohhDSU5muPdus2e29kgVQAqdj")
    device_label_list = ["load-balancer", "network.device.web-ui", "network.device.vpn", "network-administration",
                         "file-sharing", "remote-access", "database", "web.control-panel.hosting", "open-dir",
                         "login-page", "default-landing-page", "wordpress", "joomla", "ghost", "laravel", "hugo",
                         "site-kit", "yoast-seo", "elementor", "woocommerce", "gitlab", "react", "angularjs",
                         "vue.js", "jquery", "bootstrap", "font-awesome", "google-analytics", "google-tag-manager", "google-adsense",
                         "voip", "scada", "web-application-firewall", "tarpit", "bulletproof", "digicert-revoked-dcv",
                         "jquery-migrate", "jquery-ui", "prototype", "requirejs", "moment.js", "underscore.js",
                         "datatables", "clipboard.js", "backbone.js", "fancybox", "slick", "lightbox", "select2",
                         "owl-carousel", "modernizr", "glyphicons", "stimulus", "extjs", "nvd3", "camera", "printer",
                         "iot"]

    for device_label in device_label_list:
        base_path_v4 = os.path.join(cs.save_path, f"dataset/v4/{device_label}")
        base_path_v6 = os.path.join(cs.save_path, f"dataset/v6/{device_label}")
        if os.path.exists(base_path_v4) or os.path.exists(base_path_v6):
            continue
        else:
            os.mkdir(base_path_v4)
            os.mkdir(base_path_v6)
            cs.acquire_mqtt_backends(device_label, "v4")
            cs.acquire_mqtt_backends(device_label, "v6")
