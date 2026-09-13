import argparse
import socket
import time
from shared.discovery import TapoDeviceDiscoveryClient

parser = argparse.ArgumentParser()
parser.add_argument("--port",  type=int, default=20002)

args = parser.parse_args()

client = TapoDeviceDiscoveryClient(args.port)

try:
    while True:
        client.broadcast()

        response_packet = client.recv()
        if response_packet:
            print("response:", response_packet.payload)

        time.sleep(1)
except KeyboardInterrupt:
    pass