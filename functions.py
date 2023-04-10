#!/usr/bin/env python3
import subprocess


def mac_changer(interface,new_mac):
    print("[+] Changing the MAC address of your " + interface + " to " + new_mac)
    subprocess.call("ifconfig " + interface + " down", shell=True)
    subprocess.call("ifconfig " + interface + " hw ether " + new_mac, shell=True)
    subprocess.call("ifconfig " + interface + " up", shell=True)


##start of the program
print("___  ___  ___  _____   _____  _   _   ___   _   _ _____  ___________ ")
print("|  \/  | / _ \/  __ \ /  __ \| | | | / _ \ | \ | |  __ \|  ___| ___ ")
print("| .  . |/ /_\ \ /  \/ | /  \/| |_| |/ /_\ \|  \| | |  \/| |__ | |_/ /")
print("| |\/| ||  _  | |     | |    |  _  ||  _  || . ` | | __ |  __||    / ")
print("| |  | || | | | \__/\ | \__/\| | | || | | || |\  | |_\ \| |___| |\ \ ")
print("\_|  |_/\_| |_/\____/  \____/\_| |_/\_| |_/\_| \_/\____/\____/\_| \_|")

print("------------------------------------------------------------------------")
interface = input("interface >")
new_mac = input("Disposable mac >")

mac_changer(interface, new_mac)

