import argparse
from base64 import b64decode
import json
import os
import subprocess
from client.tapo_wifi_client import TapoWifiClient
from client.tapo_eu_wap_client import TapoWapClient
from shared.discovery import TapoDeviceDiscoveryClient

parser = argparse.ArgumentParser()
parser.add_argument("--address", default=None)
parser.add_argument("--username")
parser.add_argument("--password")
parser.add_argument("--configure", action=argparse.BooleanOptionalAction, default=False)
parser.add_argument("--wireless-key-type")
parser.add_argument("--wireless-ssid")
parser.add_argument("--wireless-password")
parser.add_argument("--encrypt-type")

args = parser.parse_args()

wap_client = TapoWapClient()

if not os.path.exists(".token.json"):
    if not args.username:
        raise ValueError("username is mandatory")

    if not args.password:
        raise ValueError("password is mandatory")

    resp = wap_client.do_login(args.username, args.password)
    with open(".token.json", "w") as f:
        json.dump(resp["token"], f)
else:
    with open(".token.json", "r") as f:
        wap_client.token = json.load(f)

device_id = None
client_address = args.address
factory_default = None
factory_access_point_name = None

if args.configure:
    process = subprocess.run(["nmcli", "-t", "dev", "wifi", "list"], capture_output=True, check=True)
    access_points = map(lambda x: x.replace("\\:", "-").split(":"), process.stdout.decode().split("\n"))
    first_access_point_name = next(filter(lambda x: x[2].startswith("Tapo_Plug_"), access_points), None)

    if not first_access_point_name:
        print("no access point found with SSID begin with Tapo_Plug_ !")
        exit(-1)

    print(first_access_point_name)

    factory_access_point_name = first_access_point_name[2]
    subprocess.run(["nmcli", "dev", "wifi", "connect", factory_access_point_name], check=True)

    try:
        found = TapoDeviceDiscoveryClient.discover()

        print("Found", found)

        device_id = found["device_id"]
        client_address = found["ip"]
        factory_default = found["factory_default"]
        encrypt_type = found["mgt_encrypt_schm"]["encrypt_type"]
    except KeyboardInterrupt:
        exit()
elif not client_address:
    raise ValueError("address is mandatory")
else:
    encrypt_type = "KLAP"

encrypt_type = args.encrypt_type if args.encrypt_type else encrypt_type
username = args.username if not factory_default else "test@tp-link.net"
password = args.password if not factory_default else "test"

wifi_client = TapoWifiClient(f"http://{client_address}", encrypt_type, username, password)

if args.configure:
    print(wifi_client.quick_setup_component_nego())

    wireless_scan_info = wifi_client.get_wireless_scan_info()

    target_acces_point = next(filter(lambda x: b64decode(x["ssid"]).decode() == args.wireless_ssid, wireless_scan_info["ap_list"]), None)

    def _print_access_point(access_point):
        print(
            "cipher_type:", access_point["cipher_type"],
            "bssid:", access_point["bssid"],
            "channel:", access_point["channel"],
            "ssid:", b64decode(access_point["ssid"]).decode(),
            "key_type:", access_point["key_type"],
            "signal_level:", access_point["signal_level"]
        )

    if target_acces_point:
        _print_access_point(target_acces_point)

        if not args.wireless_key_type:
            args.wireless_key_type = target_acces_point["key_type"]

            print(f"use {args.wireless_key_type} key type")
        elif args.wireless_key_type and target_acces_point["key_type"] != args.wireless_key_type:
            print(f"WARNING: requested {args.wireless_key_type} key type mismatch with {target_acces_point["key_type"]} !")
    else:
        print(f"WARNING: {args.wireless_ssid} SSID not found !")

        for access_point in wireless_scan_info["ap_list"]:
            _print_access_point(access_point)

    print(wifi_client.get_inherit_info(args.username))

    print("quick setup, waiting...")
    wifi_client.set_quick_setup_info(args.username, args.password, args.wireless_key_type, args.wireless_ssid, args.wireless_password)

    subprocess.run(["nmcli", "connnection", "delete", "id", factory_access_point_name], check=True)

    print(f"discovering device {device_id}")
    device = TapoDeviceDiscoveryClient.discover(device_id=device_id)
    print("device:", device)

    assert device["factory_default"] == False

    client_address = device["ip"]
    encrypt_type = found["mgt_encrypt_schm"]["encrypt_type"]

    wifi_client = TapoWifiClient(f"http://{client_address}", encrypt_type, args.username, args.password)

device_info = wifi_client.get_device_info()
print(device_info)
print(wifi_client.quick_setup_component_nego())
#print(wifi_client.set_device_info(True))
print(wifi_client.get_energy_usage())
#print(wifi_client.get_device_running_info())
#print(wifi_client.get_electricity_price_config())
#print(wifi_client.get_next_event())
print(wifi_client.get_current_power())
#print(wifi_client.get_latest_fw())
print("---")
#print(wifi_client.component_nego())
# Past 24 Hours
print(wifi_client.get_power_data_past_hours(24, 5))
# Past 7 days
print(wifi_client.get_power_data_past_hours(7 * 24, 60))
print(wifi_client.get_energy_data_past_hours(1, 60))
print(wifi_client.get_energy_data_past_hours(1, 24 * 60))
print(wifi_client.get_energy_data_past_hours(1, 12 * 60 * 60))
#print(wifi_client.heart_beat())
#print(wifi_client.get_server_info())
#print(wifi_client.get_latest_fw())
#print(wifi_client.get_fw_download_state())
#print(wifi_client.get_device_time())
print(wifi_client.get_schedule_rules())
#print(wifi_client.get_schedule_next_action())
#print(wifi_client.get_schedule_day_runtime())
#print(wifi_client.get_schedule_month_runtime())
#print(wifi_client.get_countdown_rules())
#print(wifi_client.get_antitheft_rules())
#print(wifi_client.set_device_time())
#print(wifi_client.set_schedule_all_enable())
#print(wifi_client.set_antitheft_all_enable())
##print(wifi_client.device_reset())
##print(wifi_client.device_reboot())
#print(wifi_client.set_wireless_info())
#print(wifi_client.add_schedule_rule())
"""print(wifi_client.edit_schedule_rule("S4", False, RuleMode.REPEAT, 22, 65, 6, 2024, 0, RuleTimeType.NORMAL, 0, "none", RuleTimeType.NORMAL, 0, {
    "on": True
}))"""
#print(wifi_client.remove_schedule_rules())
#print(wifi_client.remove_all_schedule_runtime())
#print(wifi_client.add_countdown_rule())
#print(wifi_client.edit_countdown_rule())
#print(wifi_client.remove_countdown_rules())
#print(wifi_client.add_antitheft_rule())
#{'enable': False, 'end_min': 360, 'end_time_offset': 0, 'end_time_type': 'normal', 'frequency': 5, 'id': 'A1', 'mode': 'once', 'start_min': 1170, 'start_time_offset': 0, 'start_time_type': 'normal', 'week_day': 0}
#print(wifi_client.edit_antitheft_rule(False, ))
#print(wifi_client.remove_antitheft_rules())
#print(wifi_client.multiple_request())
print(wifi_client.get_led_info())
print(wifi_client.get_protection_power())
print(wifi_client.get_max_power())
print(wifi_client.get_auto_off_config())
#print(wifi_client.set_auto_off_config(False, 3919))
#print(wifi_client.set_protection_power(False, 120))
print(wifi_client.get_auto_update_info())
#print(wifi_client.set_auto_update_info(False, 120, 180))
"""print(wifi_client.set_led_info("night_mode", {
    "start_time": 1200,
    "end_time": 420,
    "night_mode_type": "custom"
}))"""
#print(wifi_client.add_antitheft_rule(True, 5, "once", 0, "normal", 1170, 0, "normal", 360, 0))
print(wifi_client.get_energy_data(1711926000, 1718661600, 1440)) # Month
print(wifi_client.get_energy_data(1704067200, 1735686000, 43200)) # Year
print(wifi_client.get_energy_data(1718060400, 1718661600, 60)) # Day
print(wifi_client.get_power_data(1719148500, 1719062100, 5))
print(wifi_client.get_power_data(1719151200, 1718546400, 60))
#print(wifi_client.set_electricity_price_config("constant", 10000))

"""print(wap_client.passtrough(device_info["device_id"], {
    "system": {
        "get_sysinfo": None
    }
}))"""
#print(wap_client.get_account_info(username))
#print(wap_client.get_app_versions("com.tplink.iot", "en_US", "Android", 1438))
#print(wap_client.get_cloud_account_status(username))
device_info = wap_client.get_device_info(device_info["device_id"])
print(device_info)
#print(wap_client.get_device_list())
#print(wap_client.get_device_user_info(device_info["deviceId"]))
#print(wap_client.get_fw_download_progress(device_info["deviceId"]))
print(wap_client.get_intl_fw_list(device_info["deviceId"],
                                device_info["fwId"],
                                device_info["hwId"],
                                device_info["oemId"],
                                device_info["fwVer"].split(" ")[0]))
"""print(wap_client.get_int_fw_versions(device_info["deviceId"],
                                    device_info["fwId"],
                                    device_info["hwId"],
                                    device_info["oemId"],
                                    device_info["fwVer"].split(" ")[0],
                                    "en_US"))"""
#print(wap_client.get_legal_info())
#print(wap_client.get_newest_app_version("com.tplink.iot", "en_US", "Android"))
#print(wap_client.get_notice())