import pywifi
import csv
import os
import subprocess
import logging
import time
import requests
from dotenv import load_dotenv
from pywifi import const
from scapy.all import ARP, Ether, srp, sniff, Dot11Deauth

load_dotenv()
WIFI_SCAN_RESULTS_FILE = "wifi_scan_results.csv"
ROGUE_APS_FILE = "rogue_aps.csv"
MAC_SPOOFING_FILE = "mac_spoofing.csv"
DEAUTH_ATTACK_LOG = "deauth_attacks.csv"
DEFAULT_IP_RANGE = "192.168.1.1/24"

WIFI_SCAN_HEADERS = ["SSID", "Signal", "Security", "BSSID"]
ROGUE_APS_HEADERS = ["SSID", "BSSID"]
MAC_SPOOFING_HEADERS = ["MAC Address", "IP 1", "IP 2"]
DEAUTH_ATTACK_HEADERS = ["Time", "Attacker MAC", "Target MAC"]


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")  
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")      

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    
    try:
        response = requests.post(url, data=data)
        if response.status_code == 200:
            print("Telegram alert sent successfully!")
        else:
            print(f"Failed to send alert: {response.text}")
    except Exception as e:
        print(f"Error sending Telegram alert: {e}")

def scan_wifi():
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(2)  
        networks = iface.scan_results()
        
        wifi_data = []
        for net in networks:
            security = "Open" if not net.akm else "Secured"
            ssid = net.ssid if net.ssid else "Hidden SSID"
            wifi_data.append((ssid, net.signal, security, net.bssid))
            logging.info(f"SSID: {ssid}, Signal: {net.signal}, Security: {security}, BSSID: {net.bssid}")
        
        return wifi_data
    except Exception as e:
        logging.error(f"Error scanning Wi-Fi: {e}")
        return []

def detect_rogue_ap():
    try:
        rogue_aps = []
        wifi_data = scan_wifi()
        known_networks = {
             "IQOO Neo 10R":"6a:a1:ee:e7:43:a2"
        }
        
        for ssid, signal, security, bssid in wifi_data:
            if ssid in known_networks and bssid not in known_networks[ssid]:
                logging.warning(f"Rogue AP Detected: {ssid} with BSSID {bssid}")
                rogue_aps.append((ssid, bssid))
                
                alert_msg = f"🚨 Rogue AP Detected!\nSSID: {ssid}\nBSSID: {bssid}"
                send_telegram_alert(alert_msg)

        return rogue_aps
    except Exception as e:
        logging.error(f"Error detecting rogue APs: {e}")
        return []

def scan_network(ip_range=DEFAULT_IP_RANGE):
    try:
        logging.info("Scanning Network for Devices...")
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=False)[0]
        
        devices = []
        for sent, received in result:
            devices.append((received.psrc, received.hwsrc))
            logging.info(f"IP: {received.psrc}, MAC: {received.hwsrc}")
        
        return devices
    except Exception as e:
        logging.error(f"Error scanning network: {e}")
        return []

def detect_mac_spoofing():
    try:
        logging.info("Checking for MAC Address Spoofing...")
        devices = scan_network()
        mac_addresses = {}
        spoofed = []
        
        for ip, mac in devices:
            if mac in mac_addresses:
                logging.warning(f"Possible MAC Spoofing Detected: {mac} used by {ip} and {mac_addresses[mac]}")
                spoofed.append((mac, ip, mac_addresses[mac]))
                
                alert_msg = f"⚠ Possible MAC Spoofing Detected!\nMAC: {mac}\nIP 1: {ip}\nIP 2: {mac_addresses[mac]}"
                send_telegram_alert(alert_msg)
            else:
                mac_addresses[mac] = ip
        
        return spoofed
    except Exception as e:
        logging.error(f"Error detecting MAC spoofing: {e}")
        return []

def detect_deauth_attacks(packet):
    if packet.haslayer(Dot11Deauth):
        attacker_mac = packet.addr2
        target_mac = packet.addr1
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        logging.warning(f"Deauthentication attack detected! Attacker: {attacker_mac}, Target: {target_mac}")
        
        alert_msg = f"🚨 Deauth Attack Detected!\nTime: {timestamp}\nAttacker MAC: {attacker_mac}\nTarget MAC: {target_mac}"
        send_telegram_alert(alert_msg)
        
        save_results_to_csv(DEAUTH_ATTACK_LOG, [(timestamp, attacker_mac, target_mac)], DEAUTH_ATTACK_HEADERS)

def save_results_to_csv(filename, data, headers):
    try:
        with open(filename, "a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            if os.stat(filename).st_size == 0:
                writer.writerow(headers)  
            writer.writerows(data)
        logging.info(f"Results saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving results to CSV: {e}")

def real_time_monitoring():
    logging.info("Starting real-time monitoring for Deauthentication attacks...")
    sniff(iface="Wi-Fi", prn=detect_deauth_attacks, store=False)

def main():
    logging.info("Starting Wi-Fi Vulnerability Scanner...")
    wifi_data = scan_wifi()
    rogue_aps = detect_rogue_ap()
    spoofed_macs = detect_mac_spoofing()
    
    save_results_to_csv(WIFI_SCAN_RESULTS_FILE, wifi_data, WIFI_SCAN_HEADERS)
    save_results_to_csv(ROGUE_APS_FILE, rogue_aps, ROGUE_APS_HEADERS)
    save_results_to_csv(MAC_SPOOFING_FILE, spoofed_macs, MAC_SPOOFING_HEADERS)
    
    logging.info("Running real-time attack detection...")
    real_time_monitoring()

if __name__ == "__main__":
    main()