import argparse
import json
from socketserver import BaseRequestHandler, UDPServer
from shared.discovery import TDPPacket, TDPPacketFlags, TapoDeviceDiscoveryClient
from shared.error_code import ErrorCode

parser = argparse.ArgumentParser()
parser.add_argument("--server-address", default="")
parser.add_argument("--server-port",  type=int, default=TapoDeviceDiscoveryClient.DEFAULT_PORT)

parser.add_argument("--device-id", required=True)
parser.add_argument("--device-owner")
parser.add_argument("--device-type", default="SMART.TAPOPLUG")
parser.add_argument("--device-model", default="P110(US)")
parser.add_argument("--device-ip", required=True)
parser.add_argument("--device-mac", required=True)
parser.add_argument("--is-support-iot-cloud", default=True)
parser.add_argument("--factory-default", default=False)
parser.add_argument("--encrypt-type", default="KLAP")

args = parser.parse_args()

content = {
    "result":{
        "device_id": args.device_id,
        "owner": args.device_owner,
        "device_type": args.device_type,
        "device_model": args.device_model,
        "ip": args.device_ip,
        "mac": args.device_mac,
        "is_support_iot_cloud": args.is_support_iot_cloud,
        "obd_src": "tplink",
        "factory_default": args.factory_default,
        "mgt_encrypt_schm": {
            "is_support_https": False,
            "encrypt_type": args.encrypt_type,
            "http_port": 80,
            "lv": 2
        }
    },
    "error_code": ErrorCode.OK
}

response_packet = TDPPacket()
response_packet.flags = TDPPacketFlags.BROADCAST | TDPPacketFlags.REQUEST

class KasaDiscoveryUDPHandler(BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        socket = self.request[1]

        request_packet = TDPPacket()
        request_packet.decode(data)

        print("request", self.client_address)

        response_packet.sn = request_packet.sn
        response = response_packet.encode(json.dumps(content, separators=(",", ":")).encode())

        socket.sendto(response, self.client_address)

with UDPServer((args.server_address, args.server_port), KasaDiscoveryUDPHandler) as server:
    server.allow_reuse_address = True

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass