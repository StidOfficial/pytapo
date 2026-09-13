from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
import json
import re
from socketserver import TCPServer
import time
from urllib.parse import parse_qs, urlparse

from client.tapo_wifi_client import TapoWifiClient
from shared.discovery import TapoDeviceDiscoveryClient
from client.tapo_client import TapoException


class Device:
    def __init__(self, info: dict, client: TapoWifiClient):
        self.info = info
        self.client = client

class HTTPException(ValueError):
    status: HTTPStatus
    content: dict

    def __init__(self, status: HTTPStatus, content: dict):
        self.status = status
        self.content = content

class MissingArgsError(HTTPException):
    def __init__(self, missing_args: list):
        super().__init__(HTTPStatus.BAD_REQUEST, {
            "missing_args": missing_args
        })

def add_device(server: TCPServer, id: str, username: str, password: str, state: dict = None):
    device_found = TapoDeviceDiscoveryClient.discover(device_id = id)

    device_ip = device_found["ip"]
    device_encrypt_type = device_found["mgt_encrypt_schm"]["encrypt_type"]
    device = TapoWifiClient(f"http://{device_ip}", device_encrypt_type, username, password)
    if state:
        device.set_state(state)

    server.devices[id] = Device(device_found, device)

def save_server(server: TCPServer):
    for device_conf in server.config["devices"]:
        device = server.devices[device_conf["id"]].client

        device_conf["state"] = device.get_state()

    with open(".devices.json", "w") as f:
        json.dump(server.config, f)

class TapoGatewayHTTPRequestHandler(BaseHTTPRequestHandler):
    def send_json(self, content: dict = None, status: HTTPStatus = HTTPStatus.OK, headers: dict = None):
        if not headers:
            headers = {}

        if content:
            data = json.dumps(content)
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = len(data)
        else:
            data = None

        headers["Access-Control-Allow-Origin"] = "*"

        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()

        if data:
            self.wfile.write(data.encode())

    def have_required_args(self, args):
        queries = self.queries.keys()
        missing_args = list(filter(lambda x: x not in queries, args))

        if len(missing_args) > 0:
            raise MissingArgsError(missing_args)

        return True

    def do_GET(self):
        self.url = urlparse(self.path)
        self.queries = parse_qs(self.url.query)

        try:
            if self.url.path == "/devices":
                self.send_json(list(map(lambda x: x.info, self.server.devices.values())))
            elif self.url.path == "/devices/discover":
                devices = []

                tdp_client = TapoDeviceDiscoveryClient()

                last = time.time()

                while True:
                    tdp_client.broadcast()

                    payload = tdp_client.recv_payload()
                    if payload:
                        result = payload["result"]

                        if not result in devices:
                            devices.append(result)

                    if time.time() - last > 10:
                        break

                self.send_json(devices)
            elif re.search(r"/devices/(\S+)/(\S+)", self.url.path):
                match = re.search(r"/devices/(\S+)/(\S+)", self.url.path)

                device_id = match.group(1)
                function = match.group(2)

                device = self.server.devices.get(device_id)

                if not device:
                    self.send_json(status=HTTPStatus.NOT_FOUND)
                    return

                functions = ["device_info", "current_power", "server_info", "latest_fw", "fw_download_state", "schedule_rules", "led_info", "auto_off_config", "protection_power", "auto_update_info", "energy_usage", ""]

                if function in functions:
                    func = getattr(device.client, f"get_{function}")

                    self.send_json(func())
                elif function in ["power_data", "energy_data"]:
                    if not self.have_required_args(["end_timestamp", "start_timestamp", "interval"]):
                        self.send_json(status = HTTPStatus.BAD_REQUEST)
                        return

                    start_timestamp = int(self.queries["start_timestamp"][0])
                    end_timestamp = int(self.queries["end_timestamp"][0])
                    interval = int(self.queries["interval"][0])

                    if function == "power_data":
                        self.send_json(device.client.get_power_data(start_timestamp, end_timestamp, interval))
                    elif function == "energy_data":
                        self.send_json(device.client.get_energy_data(start_timestamp, end_timestamp, interval))
                else:
                    self.send_json(status = HTTPStatus.NOT_FOUND)                
            else:
                self.send_json(status = HTTPStatus.NOT_FOUND)
        except HTTPException as e:
            self.send_json(e.content, e.status)
        except TapoException as e:
            self.send_json({
                "error": {
                    "code": e.error_code,
                    "msg": e.msg
                }
            }, HTTPStatus.BAD_REQUEST)

    def do_OPTIONS(self):
        headers = {
            "Access-Control-Allow-Headers": "Content-Type"
        }

        self.send_json(status = HTTPStatus.OK, headers = headers)

    def read_content(self):
        if not "Content-Type" in self.headers:
            return None
        
        content_type = self.headers["Content-Type"]
        content_length = int(self.headers["Content-Length"])
        data = self.rfile.read(content_length)

        if content_type == "application/json":
            return json.loads(data)

        return None

    def do_POST(self):
        self.url = urlparse(self.path)
        self.queries = parse_qs(self.url.query)
        content = self.read_content()

        if self.url.path == "/devices":
            device_id = content["device_id"]
            device_username = content["device_username"]
            device_password = content["device_password"]

            if device_id in server.devices:
                self.send_json({
                    "error": "Already exists"
                }, HTTPStatus.BAD_REQUEST)
                return

            server.config["devices"].append({
                "id": device_id,
                "username": device_username,
                "password": device_password
            })

            add_device(server, device_id, device_username, device_password)
            save_server(self.server)

            self.send_json(status = HTTPStatus.OK)
        elif re.search(r"/devices/(\S+)/(\S+)", self.url.path):
            match = re.search(r"/devices/(\S+)/(\S+)", self.url.path)

            device_id = match.group(1)
            function = match.group(2)

            device = self.server.devices.get(device_id)

            if not device:
                self.send_json(status=HTTPStatus.NOT_FOUND)
                return

            if function == "device_info":
                device.client.set_device_info(content["device_on"])
                self.send_json(status = HTTPStatus.OK)
            else:
                self.send_json(status = HTTPStatus.NOT_FOUND)
        else:
            self.send_json(status = HTTPStatus.NOT_FOUND)

TCPServer.allow_reuse_address = True
with TCPServer(("", 8080), TapoGatewayHTTPRequestHandler) as server:
    with open(".devices.json") as f:
        server.config = json.load(f)

    server.devices = {}

    for device_conf in server.config["devices"]:
        device_id = device_conf["id"]
        device_username = device_conf["username"]
        device_password = device_conf["password"]
        device_ip = device_conf.get("ip")
        device_encrypt_type = device_conf.get("encrypt_type")
        device_state = device_conf.get("state")

        add_device(server, device_id, device_username, device_password, device_state)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    save_server(server)