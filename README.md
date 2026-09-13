# tapo

Python library to interract with TP-Link TAPO devices (KASA and KLAP protocols).

# Device

## Configure

Use TP-Link Discovery protocol to find and register a device.

```
python3 client.py --username <EMAIL> --password <PASSWORD> --configure --wireless-ssid <SSID> --wireless-password <PASSWORD> [--wireless-key-type wpa2_psk]
```

## Emulation

```
python3 udp_discovery_server.py --device-id <DEVICE_ID> --device-ip <DEVICE_IP> --device-mac <DEVICE_MAC>
sudo python3 http_server.py
```

## Interact

```
python3 client.py --address <DEVICE_IP> --username <USERNAME> --password <PASSWORD>
```