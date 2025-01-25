import asyncio
from bleak import BleakScanner, BleakClient
import sys
import struct
import time
import datetime
import threading
import os

# Message constants
MSG_MAX_SIZE = 20
MSG_PAYLOAD_MAX_SIZE = 18
MSG_BASE_SIZE = 1

MSG_B2V_BTLE_DISCONNECT = 0x0D
MSG_B2V_CORE_PING_REQUEST = 0x16
MSG_V2B_CORE_PING_RESPONSE = 0x17
MSG_B2V_HEARTBEAT = 0x18
MSG_V2B_HEARTBEAT = 0x19
MSG_B2V_WIFI_START = 0x1A
MSG_B2V_WIFI_STOP = 0x1B
MSG_B2V_WIFI_SET_CONFIG = 0x1C
MSG_B2V_WIFI_SCAN = 0x1D
MSG_V2B_WIFI_SCAN_RESULTS = 0x1E
MSG_B2V_WIFI_SET_CONFIG_EXT = 0x1F
MSG_B2V_SSH_SET_AUTHORIZED_KEYS = 0x80
MSG_B2V_DEV_PING_WITH_DATA_REQUEST = 0x91
MSG_V2B_DEV_PING_WITH_DATA_RESPONSE = 0x92
MSG_B2V_DEV_RESTART_ADBD = 0x93
MSG_B2V_DEV_EXEC_CMD_LINE = 0x94
MSG_V2B_DEV_EXEC_CMD_LINE_RESPONSE = 0x95
MSG_B2V_MULTIPART_START = 0xF0
MSG_B2V_MULTIPART_CONTINUE = 0xF1
MSG_B2V_MULTIPART_FINAL = 0xF2
MSG_V2B_MULTIPART_START = 0xF3
MSG_V2B_MULTIPART_CONTINUE = 0xF4
MSG_V2B_MULTIPART_FINAL = 0xF5

OLD_SERVICE_UUID = "d55e356b59cc42659d5f3c61e9dfd70f"
SERVICE_UUID = "fee3"
RECV_CHAR_UUID = "30619f2d0f5441bda65a7588d8c85b45"
SEND_CHAR_UUID = "7d2a4bdad29b4152b7252491478c5cd7"
RECV_ENC_CHAR_UUID = "28c35e4cb21843cb97183d7ede9b5316"
SEND_ENC_CHAR_UUID = "045c81553d7b41bc9da00ed27d0c8a61"

# WiFiAuth constants
AUTH_NONE_OPEN = 0
AUTH_NONE_WEP = 1
AUTH_NONE_WEP_SHARED = 2
AUTH_IEEE8021X = 3
AUTH_WPA_PSK = 4
AUTH_WPA_EAP = 5
AUTH_WPA2_PSK = 6
AUTH_WPA2_EAP = 7

def format_uuid(uuid_str):
    return f"{uuid_str[:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:]}"

class Victor:
    def __init__(self, client, send_char_uuid, recv_char_uuid, output_callback):
        self._client = client
        self._send_char_uuid = format_uuid(send_char_uuid)
        self._recv_char_uuid = format_uuid(recv_char_uuid)
        self._output = output_callback
        self._outgoing_queue = asyncio.Queue()
        self._incoming_packets = []
        self._heartbeat_counter = 0
        self._print_heartbeats = False
        self._fixing_date = True
        self._running = True

    async def start(self):
        # Start notification
        await self._client.start_notify(self._recv_char_uuid, self.handleMessage)
        # Start send loop
        asyncio.create_task(self.send_loop())
        # Send initial command to get the date
        await asyncio.sleep(0.2)
        await self.sendCommand(["date", "+%Y"])

    async def stop(self):
        await self._client.stop_notify(self._recv_char_uuid)
        self._running = False

    async def send_loop(self):
        while self._running:
            try:
                packet = await self._outgoing_queue.get()
                if packet:
                    await self._client.write_gatt_char(self._send_char_uuid, packet)
                await asyncio.sleep(0.01)
            except Exception as e:
                self._output(f"Error in send loop: {e}")
                break

    async def _send(self, buffer):
        await self._outgoing_queue.put(buffer)

    async def send(self, msgID, body=None):
        size = MSG_BASE_SIZE
        if body:
            size += len(body)
        buf = bytearray()
        buf.append(size)
        buf.append(msgID)
        if body:
            buf.extend(body)
        if len(buf) > MSG_MAX_SIZE:
            off = 0
            while off < len(buf):
                msgSize = MSG_BASE_SIZE
                if off == 0:
                    id = MSG_B2V_MULTIPART_START
                    msgSize += MSG_PAYLOAD_MAX_SIZE
                elif (len(buf) - off) > MSG_PAYLOAD_MAX_SIZE:
                    id = MSG_B2V_MULTIPART_CONTINUE
                    msgSize += MSG_PAYLOAD_MAX_SIZE
                else:
                    id = MSG_B2V_MULTIPART_FINAL
                    msgSize += (len(buf) - off)
                mhdr = bytearray([msgSize, id])
                mbuf = mhdr + buf[off:off + msgSize - 1]
                await self._send(mbuf)
                off += (msgSize - MSG_BASE_SIZE)
        else:
            await self._send(buf)

    async def sendCommand(self, args):
        body = bytearray()
        for arg in args:
            arg_bytes = bytearray(arg.encode('utf-8')) + b'\x00'
            body += arg_bytes
        await self.send(MSG_B2V_DEV_EXEC_CMD_LINE, body)

    async def syncTime(self):
        timestamp = int(time.time())
        old_date_set_args = ["date", "-u", "@" + str(timestamp)]
        await self.sendCommand(old_date_set_args)
        date_set_args = ["date", "-u", "-s", "@" + str(timestamp)]
        await self.sendCommand(date_set_args)
        setprop_args = ["setprop", "persist.sys.timezone", time.tzname[0]]
        await self.sendCommand(setprop_args)
        date_display_args = ["date"]
        await self.sendCommand(date_display_args)

    async def handleMessage(self, sender, data):
        # data is a bytearray
        if not data or len(data) < 2:
            return
        size = data[0]
        msgID = data[1]
        if msgID == MSG_V2B_CORE_PING_RESPONSE:
            self._output("Ping Response")
            return
        elif msgID == MSG_V2B_HEARTBEAT:
            self._heartbeat_counter = data[2]
            if self._print_heartbeats:
                self._output(f"Heartbeat {self._heartbeat_counter}")
            return
        elif msgID == MSG_V2B_WIFI_SCAN_RESULTS:
            # Implement parsing of WiFi scan results
            # Similar to the JS code
            offset = 2
            results = ""
            while offset < len(data):
                auth = data[offset]
                offset += 1
                encrypted = data[offset]
                offset += 1
                wps = data[offset]
                offset += 1
                signal_level = data[offset]
                offset += 1
                end = data.find(0, offset)
                if end < offset:
                    return
                ssid_bytes = data[offset:end]
                ssid = ssid_bytes.decode('utf-8', errors='replace')
                offset = end + 1
                auth_name = {
                    AUTH_NONE_OPEN: "None",
                    AUTH_NONE_WEP: "WEP",
                    AUTH_NONE_WEP_SHARED: "WEP Shared",
                    AUTH_IEEE8021X: "IEEE8021X",
                    AUTH_WPA_PSK: "WPA PSK",
                    AUTH_WPA_EAP: "WPA EAP",
                    AUTH_WPA2_PSK: "WPA2 PSK",
                    AUTH_WPA2_EAP: "WPA2 EAP"
                }.get(auth, f"Unknown ({auth})")
                result_line = f"{auth_name}\t"
                result_line += "Encrypted\t" if encrypted else "Not Encrypted\t"
                result_line += "WPS\t" if wps else "\t"
                result_line += "*" * signal_level + "\t" + ssid + "\n"
                results += result_line
            self._output(results)
            return
        elif msgID == MSG_V2B_DEV_EXEC_CMD_LINE_RESPONSE:
            response = data[2:].decode('utf-8', errors='replace')
            if self._fixing_date:
                self._fixing_date = False
                if response.startswith("1970"):
                    await self.syncTime()
            else:
                self._output(response)
            return
        elif msgID == MSG_V2B_MULTIPART_START:
            self._incoming_packets = []
            self._incoming_packets.append(data)
            return
        elif msgID == MSG_V2B_MULTIPART_CONTINUE:
            self._incoming_packets.append(data)
            return
        elif msgID == MSG_V2B_MULTIPART_FINAL:
            self._incoming_packets.append(data)
            total_length = sum(len(pkt) - 2 for pkt in self._incoming_packets)
            buf = bytearray()
            for pkt in self._incoming_packets:
                buf.extend(pkt[2:])
            # Recursively handle the reassembled message
            await self.handleMessage(sender, buf)
            self._incoming_packets = []
            return
        else:
            return

    async def disconnect(self):
        await self._client.disconnect()

async def main():
    # Main function
    output_queue = asyncio.Queue()
    victor = None
    devices = {}
    connected = False

    # Function to output messages
    def output_response(line):
        if line:
            print("\n" + line)

    # Function to handle user input
    async def handle_user_input():
        while True:
            line = await asyncio.get_event_loop().run_in_executor(None, input, "victor-ble-cli$ ")
            await process_command(line.strip())

    # Function to process commands
    async def process_command(line):
        nonlocal victor, connected
        args = line.strip().split()
        if not args:
            return
        cmd = args[0]
        if cmd == 'help':
            print_help()
        elif cmd == 'quit':
            if connected and victor:
                await victor.send(MSG_B2V_BTLE_DISCONNECT)
                await asyncio.sleep(0.03)
                await victor.disconnect()
            sys.exit()
        elif cmd == 'print-heartbeats':
            if connected and victor:
                victor._print_heartbeats = not victor._print_heartbeats
                if victor._print_heartbeats:
                    output_response(f"Heartbeat printing is now on. Current count is {victor._heartbeat_counter}")
                else:
                    output_response("Heartbeat printing is now off")
            else:
                output_response("Not connected to a Victor")
        elif cmd == 'scan':
            if connected:
                output_response("Disconnect from Victor first")
            else:
                print("Scanning for devices...")
                devices_found = await BleakScanner.discover()
                devices.clear()
                for d in devices_found:
                    if d.name and (d.name.startswith("VICTOR") or d.name.startswith("Vector")):
                        devices[d.name] = d
                        print(f"Found {d.name} ({d.address})")
        elif cmd == 'stop-scan':
            # Not needed in Bleak
            pass
        elif cmd == 'connect':
            if connected:
                output_response("You are already connected to a victor")
            else:
                if not devices:
                    output_response("No victors found to connect to.")
                    return
                local_name = list(devices.keys())[0]
                if len(args) > 1:
                    local_name = args[1]
                device = devices.get(local_name)
                if not device:
                    output_response(f"Couldn't find victor named {local_name}")
                    return
                print(f"Connecting to {local_name} ({device.address})...")
                client = BleakClient(device)
                try:
                    await client.connect()
                    print(f"Connected to {local_name}")
                    victor = Victor(client, SEND_CHAR_UUID, RECV_CHAR_UUID, output_response)
                    await victor.start()
                    connected = True
                except Exception as e:
                    output_response(f"Error connecting: {e}")
        elif cmd == 'disconnect':
            if connected and victor:
                await victor.send(MSG_B2V_BTLE_DISCONNECT)
                await asyncio.sleep(0.03)
                await victor.disconnect()
                connected = False
                victor = None
            else:
                output_response("Not connected to a Victor")
        elif cmd == 'ping':
            if connected and victor:
                await victor.send(MSG_B2V_CORE_PING_REQUEST)
            else:
                output_response("Not connected to a Victor")
        elif cmd == 'wifi-scan':
            if connected and victor:
                await victor.send(MSG_B2V_WIFI_SCAN)
            else:
                output_response("Not connected to a Victor")
        elif cmd == 'wifi-set-config':
            if connected and victor:
                if len(args) < 4:
                    output_response("wifi-set-config <none|wep|psk> <hidden> <ssid> <passphrase>")
                    output_response("passphrase required for wep and psk. ignored for none")
                    return
                buf = bytearray(2)
                if args[1] == 'wep':
                    buf[0] = AUTH_NONE_WEP
                elif args[1] == 'psk':
                    buf[0] = AUTH_WPA2_PSK
                elif args[1] == 'none':
                    buf[0] = AUTH_NONE_OPEN
                else:
                    output_response("valid security types are wep, psk, and none")
                    return
                if buf[0] != AUTH_NONE_OPEN and len(args) < 5:
                    output_response("passphrase is required if security type is wep or psk")
                    return
                true_set = set(["true", "True", "TRUE", "1", "on", "hidden", True, 1])
                buf[1] = 0x01 if args[2] in true_set else 0x00
                ssid_bytes = args[3].encode('utf-8') + b'\x00'
                buf.extend(ssid_bytes)
                if buf[0] != AUTH_NONE_OPEN:
                    passphrase_bytes = args[4].encode('utf-8') + b'\x00'
                    buf.extend(passphrase_bytes)
                else:
                    buf.extend(b'\x00')
                if buf[0] == AUTH_WPA2_PSK and buf[1] == 0x00:
                    # Send the old configuration for old robots that have not been updated
                    # to support MSG_B2V_WIFI_SET_CONFIG_EXT
                    old_buf = bytearray()
                    old_buf.extend(args[3].encode('utf-8') + b'\x00')
                    old_buf.extend(args[4].encode('utf-8') + b'\x00')
                    await victor.send(MSG_B2V_WIFI_SET_CONFIG, old_buf)
                await victor.send(MSG_B2V_WIFI_SET_CONFIG_EXT, buf)
            else:
                output_response("Not connected to a Victor")
        elif cmd == 'wifi-start':
            if connected and victor:
                await victor.send(MSG_B2V_WIFI_START)
            else:
                output_response("Not connected to a Victor")
        elif cmd == 'wifi-stop':
            if connected and victor:
                await victor.send(MSG_B2V_WIFI_STOP)
            else:
                output_response("Not connected to a Victor")
        elif cmd == 'restart-adb':
            if connected and victor:
                await victor.send(MSG_B2V_DEV_RESTART_ADBD)
            else:
                output_response("Not connected to a Victor")
        elif cmd == 'ssh-set-authorized-keys':
            if connected and victor:
                if len(args) < 2:
                    output_response("Usage: ssh-set-authorized-keys file")
                    return
                filepath = args[1]
                try:
                    with open(filepath, 'r') as f:
                        data = f.read()
                    await victor.send(MSG_B2V_SSH_SET_AUTHORIZED_KEYS, data.encode('utf-8'))
                except Exception as e:
                    output_response(f"Error reading file: {e}")
            else:
                output_response("Not connected to a Victor")
        elif cmd == 'sync-time':
            if connected and victor:
                await victor.syncTime()
            else:
                output_response("Not connected to a Victor")
        else:
            # Treat as a command to send to Victor
            if connected and victor:
                await victor.sendCommand(args)
            else:
                output_response("Not connected to a Victor")

    # Function to print help
    def print_help():
        help_text = """Commands:
        help                                  -  This message
        quit                                  -  Exit this app
        scan                                  -  Search for Victors advertising via BLE. Could take a minute.
        connect [name]                        -  Connect to a Victor by name. Defaults to first found
        disconnect                            -  Disconnect from Victor
        ping                                  -  Ping Victor
        print-heartbeats                      -  Toggle heartbeat printing for connected Victor (off by default)
        reboot [boot arg]                     -  Reboot Victor
        restart-adb                           -  Restart adb on Victor
        ssh-set-authorized-keys file          -  Use file as the ssh authorized_keys file on Victor
        sync-time                             -  Set the clock on Victor to match the host clock
        wifi-scan                             -  Ask Victor to scan for WiFi access points
        wifi-set-config <none|wep|psk> <hidden> <ssid> <passphrase> - Set WiFi access point config to Victor
           ex. wifi-set-config psk false AnkiGuest ThePassword
           ex. wifi-set-config wep false dd-wrt 7A41B23F69
           ex. wifi-set-config none false coffeeshop
           ex. wifi-set-config psk true TopSecret ThePassword
        wifi-start                            -  Bring WiFi interface up
        wifi-stop                             -  Bring WiFi interface down
        wpa_cli args                          -  Execute wpa_cli with arguments on Victor
        ifconfig [args]                       -  Execute ifconfig on Victor
        dhcptool [args]                       -  Execute dhcptool on Victor"""
        output_response(help_text)

    # Start handling user input
    asyncio.create_task(handle_user_input())

    # Keep the main function running
    while True:
        await asyncio.sleep(1)

# Run the main function
asyncio.run(main())
