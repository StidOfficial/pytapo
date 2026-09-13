from base64 import b64decode, b64encode
import hashlib
from http import HTTPStatus
import json
import math
import os
import time

import requests
from requests.exceptions import ReadTimeout
from shared.cipher.kasa import KasaCipher
from client.tapo_client import TapoClient
from shared.cipher.klap import KLAPv2Cipher
from shared.shared import RuleMode, RuleTimeType


class RuleIdParams:
    def __init__(self, id):
        self.id = id

class TapoWifiClient(TapoClient):
    TERMINAL_UUID = "6D2C312ACD071B0C46E6D71387C8A1F3"

    def __init__(self,
                 base_url: str,
                 encrypt_type: str,
                 username: str = "test@tp-link.net",
                 password: str = "test"):
        super().__init__(f"{base_url}/app")

        self.encrypt_type = encrypt_type
        self.username = username
        self.password = password

        self.cipher = None

        if self.encrypt_type == "AES":
            self.private_key = KasaCipher.generate_private_key()
            self.public_key = self.private_key.public_key()
        elif self.encrypt_type == "KLAP":
            pass
        else:
            raise ValueError(f"unsupported encrypt_type ({self.encrypt_type})")

    def set_state(self, state: dict):
        token = state["token"]
        cookies = state["cookies"]
        cipher = state["cipher"]

        if token:
            self.token = token

        if cookies:
            for k, v in cookies.items():
                self.session.cookies[k] = v

        if cipher:
            if self.encrypt_type == "AES":
                key = b64decode(cipher["key"])
                iv = b64decode(cipher["iv"])
                self.cipher = KasaCipher(key, iv)
            elif self.encrypt_type == "KLAP":
                self.cipher = KLAPv2Cipher()
                self.cipher.lsk = b64decode(cipher["lsk"])
                self.cipher.ldk = b64decode(cipher["ldk"])
                self.cipher.ivb = b64decode(cipher["ivb"])
                self.cipher.seq = cipher["seq"]
            else:
                raise ValueError(f"unsupported encrypt_type ({self.encrypt_type})")

    def get_state(self) -> dict:
        state = {
            "token": self.token,
            "cookies": self.session.cookies.get_dict(),
            "cipher": {}
        }

        if not self.cipher:
            return None

        if self.encrypt_type == "AES":
            state["cipher"]["key"] = b64encode(self.cipher.key).decode()
            state["cipher"]["iv"] = b64encode(self.cipher.iv).decode()
        elif self.encrypt_type == "KLAP":
            state["cipher"]["lsk"] = b64encode(self.cipher.lsk).decode()
            state["cipher"]["ldk"] = b64encode(self.cipher.ldk).decode()
            state["cipher"]["ivb"] = b64encode(self.cipher.ivb).decode()
            state["cipher"]["seq"] = self.cipher.seq
        else:
            raise ValueError(f"unsupported encrypt_type ({self.encrypt_type})")

        return state

    def decode_handshake(self, data: bytes):
        do_final = KasaCipher.decode_handshake(self.private_key, data)
        if not do_final:
            raise ValueError("decryption failed")

        if len(do_final) != 32:
            raise ValueError("invalid size")

        return KasaCipher(do_final[0:16], do_final[16:])

    def handshake(self):
        return self.post_request("handshake", {
            "key": KasaCipher.get_public_key(self.public_key)
        })

    def handshake1(self, seed: bytes):
        return self._post_html("/handshake1", seed)

    def handshake2(self, data: bytes):
        return self._post_html("/handshake2", data)

    def secure_passtrough(self, request_json: dict, timeout: int = None):
        if not self.cipher:
            raise ValueError("No criphter configured")

        request = self.cipher.encrypt(json.dumps(request_json))
        response = self.post_request("securePassthrough", {
            "request": f"{request}\n"
        }, timeout)

        data = json.loads(self.cipher.decrypt(response["response"])) if response["response"] else {}
        return TapoClient.get_result(data)

    def request(self, data: dict, timeout: int = None):
        if not self.cipher:
            raise ValueError("No criphter configured")

        self.cipher.seq += 1

        request = self.cipher.encrypt(json.dumps(data))
        try:
            response = self._post_html("/request", request, {
                "seq": self.cipher.seq
            }, timeout)

            data = json.loads(self.cipher.decrypt(response))
            return TapoClient.get_result(data)
        except requests.HTTPError as e:
            if e.response.status_code != HTTPStatus.FORBIDDEN:
                raise e

            self.do_handshake(self.username, self.password)

    def secure_passtrough_request(self, method: str, params: dict = None, timeout: int = None):
        request_content = {
           "method": method
        }

        if params:
            request_content["params"] = params

        request_content["requestTimeMils"] = 0

        if self.token or self.encrypt_type == "KLAP":
            request_content["requestTimeMils"] = int(round(time.time() * 1000))
            request_content["terminalUUID"] = TapoWifiClient.TERMINAL_UUID

        if not self.cipher:
            self.do_handshake(self.username, self.password)

        if self.encrypt_type == "AES":
            return self.secure_passtrough(request_content, timeout)
        elif self.encrypt_type == "KLAP":
            return self.request(request_content, timeout)
        else:
            raise ValueError(f"unsupported encrypt_type ({self.encrypt_type})")

    def do_handshake(self, username: str, password: str):
        if self.encrypt_type == "AES":
            response = self.handshake()

            self.cipher = self.decode_handshake(b64decode(response["key"].encode()))

            if username == "test@tp-link.net":
                self.do_login_device(username, password2 = password)
            else:
                self.do_login_device(username, password)
        elif self.encrypt_type == "KLAP":
            self.cipher = KLAPv2Cipher()
            self.cipher.client_seed = os.urandom(16)
            self.cipher.auth_hash = KLAPv2Cipher.get_auth_hash(username, password)

            response = self.handshake1(self.cipher.client_seed)
            if len(response) != 48:
                raise ValueError("invalid response size")

            server_seed, server_auth_hash = response[0:16], response[16:]

            self.cipher.set_server_seed(server_seed)

            if self.cipher.get_handshake1() != server_seed + server_auth_hash:
                raise ValueError("hash check failed")

            client_auth_hash = self.cipher.get_handshake2()
            response = self.handshake2(client_auth_hash)
            if len(response) != 0:
                raise ValueError("invalid response size")

            print("lsk", self.cipher.lsk.hex())
            print("ldk", self.cipher.ldk.hex())
            print("ivb", self.cipher.ivb.hex())
            print("seq", self.cipher.seq)

    @staticmethod
    def sha_digest_username(data: str):
        digest = hashlib.sha1(data.encode()).digest()

        return digest.hex()

    def login_device(self, username: str, password: str = None, password2: str = None):
        params = {
            "username": b64encode(TapoWifiClient.sha_digest_username(username).encode()).decode()
        }

        if not password and not password2:
            raise ValueError("configure a least one password")

        if password:
            params["password"] = b64encode(password.encode()).decode()

        if password2:
            params["password2"] = b64encode(TapoWifiClient.sha_digest_username(password2).encode()).decode()

        return self.secure_passtrough_request("login_device", params)

    def do_login_device(self, username: str, password: str = None, password2: str = None):
        self.token = self.login_device(username, password, password2)["token"]

    def quick_setup_component_nego(self):
        return self.secure_passtrough_request("qs_component_nego")

    def get_wireless_scan_info(self, start_index: int = 0):
        return self.secure_passtrough_request("get_wireless_scan_info", {
                "start_index": 0
            })

    def get_inherit_info(self, username: str):
        return self.secure_passtrough_request("get_inherit_info", {
                "username": b64encode(username.encode()).decode()
            })

    def set_quick_setup_info(self,
                             account_username: str,
                             account_password: str,
                             wireless_key_type: str,
                             wireless_ssid: str,
                             wireless_password: str):
        try:
            return self.secure_passtrough_request("set_qs_info", {
                    "account": {
                        "password": b64encode(account_password.encode()).decode(),
                        "username": b64encode(account_username.encode()).decode()
                    },
                    "extra_info": {
                        "specs": "EU"
                    },
                    "time": {
                        "region": "Europe/Paris",
                        "time_diff": 60,
                        "timestamp": int(time.time())
                    },
                    "wireless": {
                        "key_type": wireless_key_type,
                        "password": b64encode(wireless_password.encode()).decode(),
                        "ssid": b64encode(wireless_ssid.encode()).decode()
                    }
                },
                timeout = 25) # should be the default system wifi timeout
        except ReadTimeout:
            pass

    def get_device_info(self):
        return self.secure_passtrough_request("get_device_info")

    def set_device_info(self, device_on: bool = False):
        return self.secure_passtrough_request("set_device_info", {
            "device_on": device_on
        })

    def get_energy_usage(self):
        return self.secure_passtrough_request("get_energy_usage")
    
    def get_device_running_info(self):
        return self.secure_passtrough_request("get_device_running_info")
    
    def get_electricity_price_config(self):
        return self.secure_passtrough_request("get_electricity_price_config")
    
    def get_next_event(self):
        return self.secure_passtrough_request("get_next_event")

    def get_current_power(self):
        return self.secure_passtrough_request("get_current_power")
    
    def get_latest_fw(self):
        return self.secure_passtrough_request("get_latest_fw")
    
    def component_nego(self):
        return self.secure_passtrough_request("component_nego")

    def get_power_data_past_hours(self, hours: int, interval: int):
        end_timestamp = TapoWifiClient.get_current_time()
        start_timestamp = end_timestamp - hours * 60 * 60

        return self.get_power_data(start_timestamp, end_timestamp, interval)

    def get_power_data(self,
                       start_timestamp: int,
                       end_timestamp: int,
                       interval: int):
        return self.secure_passtrough_request("get_power_data", {
            "end_timestamp": end_timestamp,
            "interval": interval,
            "start_timestamp": start_timestamp
        })

    def get_energy_data_past_hours(self, hours: int, interval: int):
        end_timestamp = TapoWifiClient.get_current_time()
        start_timestamp = end_timestamp - hours * 60 * 60

        return self.get_energy_data(start_timestamp, end_timestamp, interval)

    def get_energy_data(self,
                        start_timestamp: int,
                        end_timestamp: int,
                        interval: int):
        return self.secure_passtrough_request("get_energy_data", {
            "end_timestamp": end_timestamp,
            "interval": interval,
            "start_timestamp": start_timestamp
        })

    def heart_beat(self):
        return self.post_request("heart_beat")

    def get_server_info(self):
        return self.secure_passtrough_request("get_server_info")

    def get_latest_fw(self):
        return self.secure_passtrough_request("get_latest_fw")
    
    def get_fw_download_state(self):
        return self.secure_passtrough_request("get_fw_download_state")

    def get_device_time(self):
        return self.secure_passtrough_request("get_device_time")

    def get_schedule_rules(self, start_index: int = 0):
        return self.secure_passtrough_request("get_schedule_rules", {
            "start_index": start_index
        })

    def get_schedule_next_action(self):
        return self.secure_passtrough_request("get_schedule_next_action")

    def get_schedule_day_runtime(self):
        return self.secure_passtrough_request("get_schedule_day_runtime")

    def get_schedule_month_runtime(self):
        return self.secure_passtrough_request("get_schedule_month_runtime")

    def get_countdown_rules(self):
        return self.secure_passtrough_request("get_countdown_rules")

    def get_antitheft_rules(self):
        return self.secure_passtrough_request("get_antitheft_rules")

    def set_device_time(self):
        return self.secure_passtrough_request("set_device_time")

    def set_schedule_all_enable(self):
        return self.secure_passtrough_request("set_antitheft_all_enable")
    
    def set_antitheft_all_enable(self):
        return self.secure_passtrough_request("set_antitheft_all_enable")

    def device_reset(self):
        return self.secure_passtrough_request("device_reset")

    def device_reboot(self):
        return self.secure_passtrough_request("device_reboot")

    def fw_download(self):
        return self.secure_passtrough_request("fw_download")

    def set_wireless_info(self):
        return self.secure_passtrough_request("set_wireless_info")

    def add_schedule_rule(self):
        return self.secure_passtrough_request("add_schedule_rule")

    def edit_schedule_rule(self, id: str, enable: bool, mode: RuleMode, day: int, week_day: int, month: int, year: int, time_offset: int, s_type: RuleTimeType, s_min: int, e_action: str, e_type: RuleTimeType, e_min: int, desired_states: dict):
        return self.secure_passtrough_request("edit_schedule_rule", {
            "day": day,
            "desired_states": desired_states,
            "enable": enable,
            "e_action": e_action,
            "e_min": e_min,
            "e_type": e_type,
            "id": id,
            "mode": mode,
            "month": month,
            "s_min": s_min,
            "s_type": s_type,
            "time_offset": time_offset,
            "week_day": week_day,
            "year": year
        })

    def remove_schedule_rules(self, remove_all: bool, rule_list: list[RuleIdParams]):
        return self.secure_passtrough_request("remove_schedule_rules", {
            remove_all: remove_all,
            rule_list: list(map(lambda x: x.__dict__, rule_list))
        })

    def remove_all_schedule_runtime(self):
        return self.secure_passtrough_request("remove_all_schedule_runtime")

    def add_countdown_rule(self,
                           action: str,
                           delay: int,
                           desired_states: dict,
                           enable: bool,
                           id: str,
                           remain: int):
        return self.secure_passtrough_request("add_countdown_rule", {
            "action": action,
            "delay": delay,
            "desired_states": desired_states,
            "enable": enable,
            "id": id,
            "remain": remain
        })

    def edit_countdown_rule(self):
        return self.secure_passtrough_request("edit_countdown_rule")

    def remove_countdown_rules(self):
        return self.secure_passtrough_request("remove_countdown_rules")

    def add_antitheft_rule(self,
                           enable: bool,
                           frequency: int,
                           mode: str,
                           week_day: int,
                           start_time_type: str,
                           start_min: int,
                           start_time_offset: int,
                           end_time_type: str,
                           end_min: int,
                           end_time_offset: int):
        return self.secure_passtrough_request("add_antitheft_rule", {
            "enable": enable,
            "frequency": frequency,
            "mode": mode,
            "week_day": week_day,
            "start_time_type": start_time_type,
            "start_min": start_min,
            "start_time_offset": start_time_offset,
            "end_time_type": end_time_type,
            "end_min": end_min,
            "end_time_offset": end_time_offset
        })

    def edit_antitheft_rule(self,
                            enable: bool,
                            day: int,
                            week_day: int,
                            month: int,
                            year: int,
                            start_min: int,
                            start_time_offset: int,
                            start_time_type: RuleTimeType,
                            end_min: int,
                            end_time_offset: int,
                            end_time_type: RuleTimeType,
                            frequency: int,
                            id: str,
                            mode: RuleMode):
        return self.secure_passtrough_request("edit_antitheft_rule", {
            "enable": enable,
            "day": day,
            "week_day": week_day,
            "month": month,
            "year": year,
            "start_min": start_min,
            "start_time_offset": start_time_offset,
            "start_time_type": start_time_type,
            "end_min": end_min,
            "end_time_offset": end_time_offset,
            "end_time_type": end_time_type,
            "frequency": frequency,
            "id": id,
            "mode": mode
        })

    def remove_antitheft_rules(self):
        return self.secure_passtrough_request("remove_antitheft_rules")

    def multiple_request(self):
        return self.secure_passtrough_request("multipleRequest")

    def get_led_info(self):
        return self.secure_passtrough_request("get_led_info")

    def get_connect_cloud_state(self):
        return self.secure_passtrough_request("get_connect_cloud_state")

    def get_protection_power(self):
        return self.secure_passtrough_request("get_protection_power")

    def get_auto_off_config(self):
        return self.secure_passtrough_request("get_auto_off_config")

    def get_max_power(self):
        return self.secure_passtrough_request("get_max_power")

    def set_auto_off_config(self, enable: bool, delay_min: int):
        return self.secure_passtrough_request("set_auto_off_config", {
            "enable": enable,
            "delay_min": delay_min
        })

    def set_protection_power(self, enable: bool, protection_power: int):
        return self.secure_passtrough_request("set_protection_power", {
            "enable": enable,
            "protection_power": protection_power
        })

    def get_auto_update_info(self):
        return self.secure_passtrough_request("get_auto_update_info")

    def set_auto_update_info(self, enable: bool, random_range: int, time: int):
        return self.secure_passtrough_request("set_auto_update_info", {
            "enable": enable,
            "random_range": random_range,
            "time": time
        })

    def set_led_info(self, led_rule: str, night_mode: dict):
        return self.secure_passtrough_request("set_led_info", {
            "led_rule": led_rule,
            "night_mode": night_mode
        })

    def clear_energy_data(self):
        return self.secure_passtrough_request("clear_energy_data")

    def set_electricity_price_config(self, type: str, constant_price: int):
        return self.secure_passtrough_request("clear_energy_data", {
            "type": type,
            "constant_price": constant_price
        })

    @staticmethod
    def get_current_time():
        now = int(time.time())
        return math.ceil(now / 100) * 100