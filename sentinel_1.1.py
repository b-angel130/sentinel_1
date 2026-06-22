from scapy.all import ARP, Ether, srp
import time
import re
import os
from datetime import datetime

# ---------------- SETTINGS ---------------- #

target = "192.168.1.0/24"

white_list = {
    "00:1b:63:84:45:e6"
}

# ------------------------------------------ #

unknown_devices = []
offline_devices = set()
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

    elif choice == "sub":

        new_mac = input("Enter MAC: ").lower()

        if new_mac in white_list:
            white_list.remove(new_mac)
        else:
            print("MAC not found.")

    elif choice == "start":
        break

    else:
        print("Invalid option.")

print("\nStarting Sentinel...")
time.sleep(1)

while True:

    current_devices = []

    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    online_whitelist = set()
    current_unknown = []

    for _, received in result:

        ip = received.psrc
        mac = received.hwsrc.lower()

        current_devices.append(mac)

        if mac in white_list:
            online_whitelist.add(mac)

        else:

            current_unknown.append({
                "ip": ip,
                "mac": mac
            })

    offline_devices = white_list - online_whitelist

    output = ""

    output += "=" * 70 + "\n"
    output += " " * 25 + "NETWORK SENTINEL\n"
    output += "=" * 70 + "\n\n"

    output += "WHITELIST\n"
    output += "-" * 70 + "\n"

    for mac in sorted(white_list):

        if mac in online_whitelist:
            status = "✓ ONLINE "
        else:
            status = "✗ OFFLINE"

        output += f"[{status}] {mac}\n"

    output += "\n"

    output += "UNKNOWN DEVICES\n"
    output += "-" * 70 + "\n"

    if current_unknown:

        for i, device in enumerate(current_unknown, start=1):

            output += f"\nUnknown Device #{i}\n"
            output += "Vendor : Unknown\n"
            output += f"IP     : {device['ip']}\n"
            output += f"MAC    : {device['mac']}\n"

    else:

        output += "No unknown devices detected.\n"

    output += "\n"

    output += "OFFLINE DEVICES\n"
    output += "-" * 70 + "\n"

    if offline_devices:

        for mac in sorted(offline_devices):
            output += f"{mac}\n"

    else:

        output += "None\n"

    output += "\n"

    output += "=" * 70 + "\n"
    output += f"Last Scan    : {datetime.now().strftime('%H:%M:%S')}\n"
    output += f"Devices Found: {len(current_devices)}\n"
    output += f"Whitelisted : {len(online_whitelist)}\n"
    output += f"Unknown     : {len(current_unknown)}\n"
    output += f"Offline     : {len(offline_devices)}\n"
    output += "=" * 70 + "\n"

    if output != last_screen:

        os.system("cls" if os.name == "nt" else "clear")
        print(output)

        last_screen = output

    time.sleep(5)



#fa:23:29:2a:f5:a5
#78:24:af:37:13:28