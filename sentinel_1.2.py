from scapy.all import ARP, Ether, srp
import time
import re
import os
import threading
from datetime import datetime
import socket
import ipaddress
import psutil
from win11toast import toast


#  ---------------- subnet ---------------- #


def get_network():
    for interface, addresses in psutil.net_if_addrs().items():

        for addr in addresses:

            if addr.family == socket.AF_INET:

                if addr.address.startswith("127."):
                    continue

                network = ipaddress.IPv4Network(
                    f"{addr.address}/{addr.netmask}",
                    strict=False
                )

                return str(network)

    return "192.168.1.0/24"


# ---------------- Settings ---------------- #


target = get_network()
white_list = {
    "00:1b:63:84:45:e6"
}

# ------------------------------------------ #

unknown_devices = {}
offline_unknown_devices = {}
last_screen = ""

print("Current whitelist:")
for mac in white_list:
    print(mac)

while True:

    choice = input("\nType 'add', 'sub' or 'start': ").lower()

    if choice == "add":

        new_mac = input("Enter MAC: ").lower()

        if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", new_mac):
            print("Invalid MAC.")
            continue

        white_list.add(new_mac)
        print("MAC added.")

    elif choice == "sub":

        new_mac = input("Enter MAC: ").lower()

        if new_mac in white_list:
            white_list.remove(new_mac)
            print("MAC removed.")
        else:
            print("MAC not found.")

    elif choice == "start":
        break

    else:
        print("Invalid option.")

print("\nStarting Sentinel...")
print(f"Scanning subnet: {target}")
time.sleep(1)

try:
    while True:

        current_devices = set()

        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        try:
            result = srp(
                packet,
                timeout=2,
                verbose=False
            )[0]
        except Exception as e:
            print(f"Scan error: {e}. Retrying in 5 seconds...")
            time.sleep(5)
            continue

        online_whitelist = set()
        current_unknown = {}

        # ---------------- Scan ---------------- #

        for _, received in result:

            ip = received.psrc
            mac = received.hwsrc.lower()

            current_devices.add(mac)

            if mac in white_list:

                online_whitelist.add(mac)

            else:

                current_unknown[mac] = {
                    "ip": ip,
                    "mac": mac
                }

                if mac not in unknown_devices:
                    unknown_devices[mac] = {
                        "ip": ip,
                        "mac": mac
                    }


                    # Send notification in background thread so scanning continues
                    def send_notification(ip, mac):
                        try:
                            toast(
                                "🚨 NETWORK SENTINEL",
                                f"Unknown device detected!\n\nIP: {ip}\nMAC: {mac}"
                            )
                        except Exception:
                            pass


                    notification_thread = threading.Thread(
                        target=send_notification,
                        args=(ip, mac),
                        daemon=True
                    )
                    notification_thread.start()

        # ---------------- Offline devices ---------------- #

        offline_whitelist = white_list - online_whitelist

        offline_unknown_devices = {}

        for mac, device in unknown_devices.items():

            if mac not in current_unknown:
                offline_unknown_devices[mac] = device

        # ---------------- Dashboard ---------------- #

        output = ""

        output += "=" * 70 + "\n"
        output += " " * 24 + "NETWORK SENTINEL\n"
        output += "=" * 70 + "\n\n"

        # ---------- Whitelist ----------

        output += "WHITELIST\n"
        output += "-" * 70 + "\n"

        for mac in sorted(white_list):

            if mac in online_whitelist:
                output += f"[✓] {mac}\n"
            else:
                output += f"[✗] {mac}\n"

        output += "\n"

        # ---------- Unknown ----------

        output += "UNKNOWN DEVICES\n"
        output += "-" * 70 + "\n"

        if current_unknown:

            for number, device in enumerate(current_unknown.values(), start=1):
                output += f"\nUnknown Device #{number}\n"
                output += "Vendor : Unknown\n"
                output += f"IP     : {device['ip']}\n"
                output += f"MAC    : {device['mac']}\n"

        else:

            output += "No unknown devices detected.\n"

        output += "\n"

        # ---------- Offline ----------

        output += "OFFLINE DEVICES\n"
        output += "-" * 70 + "\n"

        if offline_whitelist:

            output += "\nWhitelisted Devices:\n"

            for mac in sorted(offline_whitelist):
                output += f"  {mac}\n"

        else:

            output += "\nNo offline whitelist devices.\n"

        if offline_unknown_devices:

            output += "\nPreviously Detected Unknown Devices:\n"

            for device in offline_unknown_devices.values():
                output += "\nUnknown Device\n"
                output += "Vendor : Unknown\n"
                output += f"IP     : {device['ip']}\n"
                output += f"MAC    : {device['mac']}\n"

        else:

            output += "\nNo offline unknown devices.\n"

        output += "\n"

        # ---------- Statistics ----------

        output += "=" * 70 + "\n"
        output += f"Last Scan          : {datetime.now().strftime('%H:%M:%S')}\n"
        output += f"Devices Found      : {len(current_devices)}\n"
        output += f"Whitelisted Online : {len(online_whitelist)}\n"
        output += f"Unknown Online     : {len(current_unknown)}\n"
        output += f"Offline Trusted    : {len(offline_whitelist)}\n"
        output += f"Offline Unknown    : {len(offline_unknown_devices)}\n"
        output += "=" * 70 + "\n"

        # ---------- Refresh screen only if changed ----------

        if output != last_screen:
            os.system("cls" if os.name == "nt" else "clear")
            print(output)
            last_screen = output

        time.sleep(5)

except KeyboardInterrupt:
    print("\n\nStopping Network Sentinel...")
    os.system("cls" if os.name == "nt" else "clear")

# fa:23:29:2a:f5:a5
# 78:24:af:37:13:28