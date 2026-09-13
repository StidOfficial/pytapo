
from enum import Enum, Flag
import json
import random
import socket
from zlib import crc32


class TDPPacketFlags(Flag):
    ALL = 0
    REQUEST = 1
    REPLY = 2
    COMPRESS = 4
    ENCRYPT = 8
    BROADCAST = 16
    UNICAST = 32

class TDPPacketResult(Enum):
    DEFAULT = 0
    FAILED = -1
    OK = 1

class TDPVersion(Enum):
    V1 = 1
    V2 = 2

class TDPOperationCodeDiscovery(Enum):
    V1 = 2
    V2 = 1

class TDPPacket:
    TDP_CHECKSUM_DEFAULT = 1516993677

    def __init__(self):
        self.version = TDPVersion.V2
        self.reserved = 0
        self.operation_code = None
        self.payload_len = None
        self.flags = None
        self.result = TDPPacketResult.DEFAULT
        self.sn = None
        self.checksum = None
        self.payload = None

    @staticmethod
    def generate_sn() -> int:
        return random.randint(0, 268435455)

    def decode(self, data: bytes) -> bytes:
        if len(data) < 16:
            raise ValueError("header too small")

        self.version = TDPVersion(data[0])
        self.reserved = data[1]
        self.operation_code = TDPOperationCodeDiscovery(int.from_bytes(data[2:2 + 2]))
        self.payload_len = int.from_bytes(data[4:4 + 2])
        self.flags = TDPPacketFlags(data[6])
        self.result = TDPPacketResult(data[7])
        self.sn = int.from_bytes(data[8:8 + 4])
        self.checksum = int.from_bytes(data[12:12 + 4])
        self.payload = data[16:16 + self.payload_len]

        if len(data) < self.payload_len:
            raise ValueError("invalid size")

        tmp_data = bytearray(data)
        tmp_data[12:12 + 4] = int.to_bytes(TDPPacket.TDP_CHECKSUM_DEFAULT, 4)

        if crc32(tmp_data) != self.checksum:
            raise ValueError("invalid checksum")

    def encode(self, content: bytes) -> bytes:
        data = b""

        if self.version == TDPVersion.V1:
            self.operation_code = TDPOperationCodeDiscovery.V1
        else:
            self.operation_code = TDPOperationCodeDiscovery.V2

        if content:
            self.payload_len = len(content)
        else:
            self.payload_len = 0

        self.checksum = TDPPacket.TDP_CHECKSUM_DEFAULT
        self.payload = content

        data += int.to_bytes(self.version.value, 1)
        data += int.to_bytes(self.reserved, 1)
        data += int.to_bytes(self.operation_code.value, 2)
        data += int.to_bytes(self.payload_len, 2)
        data += int.to_bytes(self.flags.value, 1)
        data += int.to_bytes(self.result.value, 1)
        data += int.to_bytes(self.sn, 4)
        data += int.to_bytes(self.checksum, 4)
        data += self.payload

        checksum = crc32(data)
        self.checksum = checksum

        tmp_data = bytearray(data)
        tmp_data[12:12 + 4] = int.to_bytes(checksum, 4)

        return bytes(tmp_data)

class TapoDeviceDiscoveryClient:
    DEFAULT_PORT = 20002

    def __init__(self, port: int = DEFAULT_PORT):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.settimeout(1.0)

        self.port = port

        self.request_packet = TDPPacket()
        self.request_packet.flags = TDPPacketFlags.BROADCAST | TDPPacketFlags.REQUEST
        self.request_packet.sn = TDPPacket.generate_sn()

    def broadcast(self):
        self.socket.sendto(self.request_packet.encode(b""), ("255.255.255.255", self.port))

    def recv(self) -> TDPPacket:
        try:
            data, _ = self.socket.recvfrom(1024)

            response_packet = TDPPacket()
            response_packet.decode(data)

            return response_packet
        except TimeoutError:
            pass

        return None

    def recv_payload(self) -> dict:
        response_packet = self.recv()
        if response_packet:
            return json.loads(response_packet.payload)

        return None

    @staticmethod
    def discover(port = DEFAULT_PORT, device_id = None):
        tdp_client = TapoDeviceDiscoveryClient(port)

        while True:
            tdp_client.broadcast()

            payload = tdp_client.recv_payload()
            if payload:
                result = payload["result"]
                if not device_id:
                    return result

                if result["device_id"] == device_id:
                    return result