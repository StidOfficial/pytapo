import argparse
from base64 import b64decode, b64encode
from datetime import datetime
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
import json
import os
import random
import socket
from socketserver import TCPServer
from urllib.parse import parse_qs, urlparse
import uuid

from shared.cipher.kasa import KasaCipher
from shared.error_code import ErrorCode
from shared.cipher.klap import KLAPv2Cipher
from shared.shared import CloudState


class TapoSession:
    def __init__(self):
        self.encrypt_type = None
        self.kasa_cipher = KasaCipher()
        self.klap_cipher = KLAPv2Cipher()

class TapoHTTPRequestHandler(BaseHTTPRequestHandler):
    cookies: SimpleCookie
    session: TapoSession

    SESSION_COOKIENAME = "TP_SESSIONID"

    def parse_request(self) -> bool:
        ret = super().parse_request()

        self.cookies = SimpleCookie()
        if self.headers["Cookie"]:
            self.cookies.load(self.headers["Cookie"])

        cookie = self.cookies.get(TapoHTTPRequestHandler.SESSION_COOKIENAME)
        self.session_id = cookie.value if cookie else None
        self.session = self.server.sessions.get(self.session_id)

        return ret

    def create_session(self):
        self.session_id = uuid.uuid4().hex.upper()

        self.session = TapoSession()
        self.server.sessions[self.session_id] = self.session

    def read_json(self):
        content_type = self.headers["Content-Type"]

        if not "application/json" in content_type:
            raise ValueError(f"{content_type} is not supported")

        content_length = int(self.headers["Content-Length"])
        return json.loads(self.rfile.read(content_length))

    def read_text(self):
        content_type = self.headers["Content-Type"]

        if not "text/plain" in content_type:
            raise ValueError(f"{content_type} is not supported")

        content_length = int(self.headers["Content-Length"])
        return self.rfile.read(content_length)

    def send(self, content: bytes, content_type: str, headers: dict = {}, code: int = HTTPStatus.OK):
        headers["Content-Type"] = content_type
        headers["Content-Length"] = len(content)

        self.send_response(code)

        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()

        self.wfile.write(content)

    def send_json(self, content: dict, headers: dict = {}):
        data = json.dumps(content)

        self.send(data.encode(), "application/json;charset=UTF-8", headers)

    def send_html(self, data: bytes = b"", headers: dict = {}, code: int = HTTPStatus.OK):
        self.send(data, "text/html", headers, code)

    def send_error(self, error_code: ErrorCode):
        self.send_json({
            "error_code": error_code.value,
            "msg": ErrorCode.get_message_error(error_code.value)
        })

    def send_secure(self, json_content):
        data = json.dumps(json_content)

        if self.session.encrypt_type == "AES":
            self.send_json({
                "error_code": ErrorCode.OK,
                "result": {
                    "response": self.session.kasa_cipher.encrypt(data)
                }
            })
        elif self.session.encrypt_type == "KLAP":
            self.send_html(self.session.klap_cipher.encrypt(data))
        else:
            raise ValueError(f"unsupported encrypt_type ({self.session.encrypt_type})")

    def version_string(self):
        return "SHIP 2.0"

    def do_GET(self):
        self.send("<html><body><center>200 OK</center></body></html>", "text/html")

    @staticmethod
    def get_local_time() -> str:
        return datetime.now().isoformat(" ", "seconds")

    def do_secure_request(self, method, params):
        if method == "login_device":
            username = b64decode(params["username"]).decode()
            password = b64decode(params["password"]).decode() if "password" in params and params["password"] else None
            password2 = b64decode(params["password2"]).decode() if "password2" in params and params["password2"] else None

            print("username", username, "password", password, "password2", password2)

            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "token": uuid.uuid4().hex.upper()
                }
            })
        elif method == "qs_component_nego":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "component_list": [
                        {"id": "quick_setup", "ver_code": 3},
                        {"id": "sunrise_sunset", "ver_code": 1},
                        {"id": "iot_cloud", "ver_code": 1},
                        {"id": "inherit", "ver_code": 1},
                        {"id": "firmware", "ver_code": 2}
                    ],
                    "extra_info": {
                        "device_type": "SMART.TAPOPLUG",
                        "device_model": "P110"
                    }
                }
            })
        elif method == "get_wireless_scan_info":
            start_index = params["start_index"]

            def ap_item(x):
                return {
                    "cipher_type": 2,
                    "bssid": os.urandom(6).hex().upper(),
                    "channel": random.randint(1, 11),
                    "ssid": b64encode(f"Wifi {x}".encode()).decode(),
                    "key_type": "wpa2_psk",
                    "signal_level": 1
                }

            access_points = list(map(ap_item, range(13)))

            def ap_pagination(x):
                index = access_points.index(x)

                return index >= start_index and index < start_index + 10

            self.send_secure({
                "result": {
                    "ap_list": list(filter(ap_pagination, access_points)),
                    "sum": len(access_points),
                    "start_index": start_index,
                    "wep_supported": False
                },
                "error_code": ErrorCode.OK
            })
        elif method == "get_inherit_info":
            username = b64decode(params["username"]).decode()

            print("username", username)

            self.send_secure({
                "result": {
                    "inherit_status": False
                },
                "error_code": ErrorCode.OK
            })
        elif method == "set_qs_info":
            account = params["account"]
            extra_info = params["extra_info"]
            time_info = params["time"]
            wireless = params["wireless"]

            account_username = b64decode(account["username"]).decode()
            account_password = b64decode(account["password"]).decode()

            extra_info_specs = extra_info["specs"]

            time_region = time_info["region"]
            time_diff = time_info["time_diff"]
            timestamp = time_info["timestamp"]

            wireless_key_type = wireless["key_type"]
            wireless_password = b64decode(wireless["password"]).decode()
            wireless_ssid = b64decode(wireless["ssid"]).decode()

            print("account_username", account_username, "account_password", account_password)
            print("extra_info_specs", extra_info_specs)
            print("time_region", time_region, "time_diff", time_diff, "timestamp", timestamp)
            print("wireless_key_type", wireless_key_type, "wireless_password", wireless_password, "wireless_ssid", wireless_ssid)
        elif method == "get_device_info":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "device_id": self.server.device_id,
                    #"fw_ver": "1.2.3 Build 230425 Rel.142542",
                    "fw_ver": "1.3.0 Build 230905 Rel.152200",
                    "hw_ver": "1.0",
                    "type": "SMART.TAPOPLUG",
                    "model": "P110",
                    "mac": self.server.mac,
                    "hw_id": self.server.hw_id,
                    "fw_id": "00000000000000000000000000000000",
                    "oem_id": self.server.oem_id,
                    "ip": self.server.ip,
                    "time_diff": 60,
                    "ssid": b64encode("Wifi 1".encode()).decode(),
                    "rssi": -90,
                    "signal_level": 1,
                    "auto_off_status": "off",
                    "auto_off_remain_time": 0,
                    "latitude": 0,
                    "longitude": 0,
                    "lang": "en_US",
                    "avatar": "",
                    "region": "Europe/Paris",
                    "specs": "",
                    "nickname": "",
                    "has_set_location_info": False,
                    "device_on": True,
                    "on_time": 330,
                    "default_states": {
                        "type": "last_states",
                        "state": {}
                    },
                    "overheated": False,
                    "power_protection_status": "normal"
                }
            })
        elif method == "set_device_info":
            device_on = params.get("device_on")
            default_states = params.get("default_states")

            print("device_on", device_on)
            print("default_states", default_states)

            self.send_secure({
                "error_code": ErrorCode.OK
            })
        elif method == "get_energy_usage":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "today_runtime": 117,
                    "month_runtime": 119,
                    "today_energy": 5,
                    "month_energy": 5,
                    "local_time": TapoHTTPRequestHandler.get_local_time(),
                    "electricity_charge": [0, 0, 0],
                    "current_power": 0
                }
            })
        elif method == "get_device_running_info":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "device_id": self.server.device_id,
                    "fw_ver": "1.2.3 Build 230425 Rel.142542",
                    "ip": self.server.ip,
                    "signal_level": 3,
                    "rssi": -45,
                    "auto_off_status": "off",
                    "auto_off_remain_time": 0,
                    "latitude": 0,
                    "longitude": 0,
                    "lang": "en_US",
                    "avatar": "plug",
                    "region": "Europe/Paris",
                    "specs": "",
                    "nickname": b64encode("Smart Plug".encode()).decode(),
                    "has_set_location_info": False,
                    "device_on": True,
                    "on_time": 188,
                    "default_states": {
                        "type": "last_states",
                        "state": {}
                    },
                    "overheated": False,
                    "power_protection_status": "normal"
                }
            })
        elif method == "get_electricity_price_config":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "type": "constant",
                    "constant_price": 0,
                    "time_of_use_config": {
                        "summer": {
                            "period": [0, 0, 0, 0],
                            "weekday_config": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                            "weekend_config": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                            "offpeak": 0,
                            "midpeak": 0,
                            "onpeak": 0
                        },
                        "winter": {
                            "period": [0, 0, 0, 0],
                            "weekday_config": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                            "weekend_config": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                            "offpeak": 0,
                            "midpeak": 0,
                            "onpeak": 0
                        }
                    }
                }
            })
        elif method == "get_next_event":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {}
            })
        elif method == "get_current_power":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "current_power": 0
                }
            })
        elif method == "get_latest_fw":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "type": 2,
                    "fw_ver": "1.3.0 Build 230905 Rel.152200",
                    "release_date": "2023-11-08",
                    "release_note": "Modifications and Bug Fixes:\n1. Improved stability and performance.\n2. Enhanced local communication security.",
                    "fw_size": 786432,
                    "hw_id": self.server.hw_id,
                    "oem_id": self.server.oem_id,
                    "need_to_upgrade": True
                }
            })
        elif method == "component_nego":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "component_list": [
                        {"id": "device", "ver_code": 2},
                        {"id": "firmware", "ver_code": 2},
                        {"id": "quick_setup", "ver_code": 3},
                        {"id": "time", "ver_code": 1},
                        {"id": "wireless", "ver_code": 1},
                        {"id": "schedule", "ver_code": 2},
                        {"id": "countdown", "ver_code": 2},
                        {"id": "antitheft", "ver_code": 1},
                        {"id": "account", "ver_code": 1},
                        {"id": "synchronize", "ver_code": 1},
                        {"id": "sunrise_sunset", "ver_code": 1},
                        {"id": "led", "ver_code": 1},
                        {"id": "cloud_connect", "ver_code": 1},
                        {"id": "iot_cloud", "ver_code": 1},
                        {"id": "device_local_time", "ver_code": 1},
                        {"id": "default_states", "ver_code": 1},
                        {"id": "auto_off", "ver_code": 2},
                        {"id": "energy_monitoring", "ver_code": 2},
                        {"id": "power_protection", "ver_code": 1}
                    ]
                }
            })
        elif method == "get_power_data":
            start_timestamp = params["start_timestamp"]
            end_timestamp = params["end_timestamp"]
            interval = params["interval"]

            if interval == 60:
                value = 1
                size = 144 # Past 7 days
            elif interval == 5:
                value = 2
                size = 144 # Past 24 Hours
            else:
                value = 3
                size = 0

            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "data": list(map(lambda _: value, range(size))),
                    "start_timestamp": start_timestamp,
                    "end_timestamp": end_timestamp,
                    "interval": interval
                }
            })
        elif method == "get_energy_data":
            start_timestamp = params["start_timestamp"]
            end_timestamp = params["end_timestamp"]
            interval = params["interval"]

            if interval == 60:
                value = 4
                size = 168 # Day
            elif interval == 43200:
                value = 5
                size = 12 # Year
            elif interval == 1440:
                value = 6
                size = 91 # Month
            else:
                value = 7
                size = 0

            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "local_time": TapoHTTPRequestHandler.get_local_time(),
                    "data": list(map(lambda _: value, range(size))),
                    "start_timestamp": start_timestamp,
                    "end_timestamp": end_timestamp,
                    "interval": interval
                }
            })
        elif method == "get_fw_download_state":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "status": 0,
                    "download_progress": 0,
                    "reboot_time": 5,
                    "upgrade_time": 5,
                    "auto_upgrade": False
                }
            })
        elif method == "get_device_time":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "time_diff": 60,
                    "timestamp": int(time.time()),
                    "region": "Europe/Paris"
                }
            })
        elif method == "get_countdown_rules":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "enable": False,
                    "antitheft_rule_max_count": 1,
                    "rule_list": []
                }
            })
        elif method == "get_antitheft_rules":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "enable": False,
                    "antitheft_rule_max_count": 1,
                    "rule_list": []
                }
            })
        elif method == "multipleRequest":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": None
            })
        elif method == "get_schedule_rules":
            start_index = params["start_index"]

            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "enable": True,
                    "schedule_rule_max_count": 32,
                    "start_index": start_index,
                    "sum": 4,
                    "rule_list": [
                        {
                            "enable": True,
                            "id": "S1",
                            "s_type": "normal",
                            "s_min": 1080,
                            "e_type": "normal",
                            "e_min": 0,
                            "e_action": "none",
                            "week_day": 62,
                            "mode": "repeat",
                            "year": 2024,
                            "month": 6,
                            "day": 17,
                            "time_offset": 0,
                            "desired_states": {
                                "on": True
                            }
                        },
                        {
                            "enable": True,
                            "id": "S2",
                            "s_type": "normal",
                            "s_min": 1320,
                            "e_type": "normal",
                            "e_min": 0,
                            "e_action": "none",
                            "week_day": 62,
                            "mode": "repeat",
                            "year": 2024,
                            "month": 6,
                            "day": 17,
                            "time_offset": 0,
                            "desired_states": {
                                "on": False
                            }
                        },
                        {
                            "enable": True,
                            "id": "S3",
                            "s_type": "normal",
                            "s_min": 480,
                            "e_type": "normal",
                            "e_min": 0,
                            "e_action": "none",
                            "week_day": 65,
                            "mode": "repeat",
                            "year": 2024,
                            "month": 6,
                            "day": 22,
                            "time_offset": 0,
                            "desired_states": {
                                "on": True
                            }
                        },
                        {
                            "enable": True,
                            "id": "S4",
                            "s_type": "normal",
                            "s_min": 0,
                            "e_type": "normal",
                            "e_min": 0,
                            "e_action": "none",
                            "week_day": 65,
                            "mode": "repeat",
                            "year": 2024,
                            "month": 6,
                            "day": 22,
                            "time_offset": 0,
                            "desired_states": {
                                "on": False
                            }
                        }
                    ]
                }
            })
        elif method == "get_led_info":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "night_mode": {
                        "night_mode_type": "sunrise_sunset",
                        "start_time": 1140,
                        "end_time": 420,
                        "sunrise_offset": 0,
                        "sunset_offset": 0
                    },
                    "led_status": True,
                    "led_rule": "always"
                }
            })
        elif method == "add_schedule_rule":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": None
            })
        elif method == "edit_schedule_rule":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {}
            })
        elif method == "get_connect_cloud_state":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "status": CloudState.CONNECTED
                }
            })
        elif method == "get_protection_power":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "enable": True,
                    "protection_power": 0
                }
            })
        elif method == "get_max_power":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "max_power": 100
                }
            })
        elif method == "get_auto_off_config":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "delay_min": 0,
                    "enable": True
                }
            })
        elif method == "add_countdown_rule":
            enable = params["enable"]
            remain = params["remain"]
            delay = params["delay"]
            desired_states = params["desired_states"]

            print(enable, remain, delay, desired_states)

            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": None
            })
        elif method == "set_auto_off_config":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": None
            })
        elif method == "set_protection_power":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": None
            })
        elif method == "get_auto_update_info":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "enable": True,
                    "time": 180,
                    "random_range": 120
                }
            })
        elif method == "set_auto_update_info":
            enable = params["enable"]
            random_range = params["random_range"]
            time = params["time"]

            print(enable, random_range, time)

            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": None
            })
        elif method == "set_led_info":
            led_rule = params["led_rule"]
            night_mode = params.get("night_mode")

            print(led_rule, night_mode)

            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "led_status": False
                }
            })
        elif method == "add_antitheft_rule":
            enable = params["enable"]
            frequency = params["frequency"]
            mode = params["mode"]
            week_day = params["week_day"]
            start_time_type = params["start_time_type"]
            start_min = params["start_min"]
            start_time_offset = params["start_time_offset"]
            end_time_type = params["end_time_type"]
            end_min = params["end_min"]
            end_time_offset = params["end_time_offset"]

            print(enable, frequency, mode, week_day)
            print(start_time_type, start_min, start_time_offset)
            print(end_time_type, end_min, end_time_offset)

            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": {
                    "id": "A1"
                }
            })
        elif method == "fw_download":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": None
            })
        elif method == "remove_schedule_rules":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": None
            })
        elif method == "clear_energy_data":
            self.send_secure({
                "error_code": ErrorCode.OK,
                "result": None
            })
        else:
            print("unknown secure passtrough method:", method)

            self.send_response(HTTPStatus.OK)
            self.end_headers()

    def do_POST(self):
        url = urlparse(self.path)
        queries = parse_qs(url.query)

        print(self.path, url.path, queries)

        if url.path == "/app/handshake1":
            client_seed = self.read_text()

            if len(client_seed) != 16:
                self.send_html(code = HTTPStatus.BAD_REQUEST)
                return

            self.create_session()
            self.session.encrypt_type = "KLAP"
            self.session.klap_cipher.server_seed = os.urandom(16)
            self.session.klap_cipher.auth_hash = self.server.auth_hash
            self.session.klap_cipher.set_client_seed(client_seed)

            print("seq", self.session.klap_cipher.seq, int.to_bytes(self.session.klap_cipher.seq, 4, signed = True).hex())

            #if self.session.klap_cipher.seq < 0:
            #    self.send_html(code = HTTPStatus.BAD_REQUEST)
            #    return

            self.send_html(self.session.klap_cipher.get_handshake1(), {
                "Set-Cookie": f"{TapoHTTPRequestHandler.SESSION_COOKIENAME}={self.session_id};TIMEOUT=86400"
            })
        elif url.path == "/app/handshake2":
            client_auth_hash = self.read_text()

            if len(client_auth_hash) != 32:
                self.send_html(code = HTTPStatus.BAD_REQUEST)
                return

            expected_client_auth_hash = self.session.klap_cipher.get_handshake2()
            if client_auth_hash != expected_client_auth_hash:
                self.send_html(code = HTTPStatus.FORBIDDEN)
                return

            self.send_html()
        elif url.path == "/app/request":
            seq = int(queries["seq"][0])

            data = self.read_text()

            if not self.session:
                self.send_html(code = HTTPStatus.BAD_REQUEST)
                return

            self.session.klap_cipher.seq += 1

            print(seq, self.session.klap_cipher.seq)
            #if seq != self.session.klap_cipher.seq:
            if self.session.klap_cipher.seq < 0:
                self.send_html(code = HTTPStatus.BAD_REQUEST)
                print("invalid seq")
                return
                #raise ValueError("invalid seq")

            self.session.klap_cipher.seq = seq

            content = json.loads(self.session.klap_cipher.decrypt(data))
            print(content)
            self.do_secure_request(content["method"], content.get("params"))
        elif url.path == "/app":
            content = self.read_json()

            if self.server.protocol != "AES":
                self.send_error(ErrorCode.DEVICE_SUPPORT_KLAP_PROTOCOL)
                return

            method = content["method"]
            if method == "handshake":
                client_public_key = content["params"]["key"]

                self.create_session()
                self.session.encrypt_type = "AES"

                self.send_json({
                    "error_code": ErrorCode.OK,
                    "result": {
                        "key": self.session.kasa_cipher.generate_handshake(client_public_key)
                    }
                }, {
                    "Set-Cookie": f"{TapoHTTPRequestHandler.SESSION_COOKIENAME}={self.session_id};TIMEOUT=86400"
                })
            elif method == "securePassthrough":
                request = content["params"]["request"]

                if not self.session:
                    self.send_error(ErrorCode.SESSION_TIMEOUT)
                    return

                try:
                    sub_request = json.loads(self.session.kasa_cipher.decrypt(request))
                    self.do_secure_request(sub_request["method"], sub_request.get("params"))
                except UnicodeDecodeError:
                    self.send_error(ErrorCode.AES_DECODE_FAIL)
                except ValueError:
                    self.send_error(ErrorCode.AES_DECODE_FAIL)
            else:
                print("unknown method:", method)

                self.send_response(HTTPStatus.OK)
                self.end_headers()
        else:
            print("unknown path:", url.path)

            self.send_response(HTTPStatus.OK)
            self.end_headers()

parser = argparse.ArgumentParser()
parser.add_argument("--username", default="test@tp-link.net")
parser.add_argument("--password", default="test")
parser.add_argument("--device-id", default=os.urandom(20).hex().upper())
parser.add_argument("--mac", default=os.urandom(6).hex("-").upper())
parser.add_argument("--hw-id", default=os.urandom(20).hex().upper())
parser.add_argument("--oem-id", default=os.urandom(16).hex().upper())

args = parser.parse_args()

TCPServer.allow_reuse_address = True
with TCPServer(("", 80), TapoHTTPRequestHandler) as server:
    server.private_key = KasaCipher.generate_private_key()
    server.public_key = server.private_key.public_key()
    server.sessions = {}
    server.protocol = "AES"
    server.auth_hash = KLAPv2Cipher.get_auth_hash(args.username, args.password)
    server.device_id = args.device_id
    server.mac = args.mac
    server.hw_id = args.hw_id
    server.oem_id = args.oem_id
    server.ip = socket.gethostbyname(socket.gethostname())

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass