import requests
import os

def check_and_update(local_path, github_raw_url):
    try:
        # GitHub'daki raw içeriği çek
        response = requests.get(github_raw_url)
        if response.status_code != 200:
            print("🟥 GitHub'dan raw içerik alınamadı.>
            return

        remote_code = response.text

        # Eğer local dosya varsa oku
        if os.path.exists(local_path):
            with open(local_path, "r", encoding="utf-8>
                local_code = f.read()
        else:
            local_code = ""

        # Kodlar aynı değilse güncelle
        if local_code != remote_code:
            with open(local_path, "w", encoding="utf-8>
                f.write(remote_code)
            print("🟩 Kod güncellendi Programı yeniden>
            exit()
        else:
            print("🟦 Kod zaten güncel Başlatılıyor...>

    except Exception as e:
        print("💥 Hata:", e)


# 🔧 Örnek kullanım
github_raw_url = "https://raw.githubusercontent.com/ca>
local_path = os.path.realpath(__file__)

check_and_update(local_path, github_raw_url)
time.sleep(3)
os.system("cls||clear")

import socket
import requests
from datetime import datetime
import whois
import concurrent.futures

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return f"Error: {e}"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        info = ""
        if w.creation_date:
            created = w.creation_date[0] if isinstance>
            info += f"Creation Date: {created}\n"
        if w.expiration_date:
            expires = w.expiration_date[0] if isinstan>
            info += f"Expiration Date: {expires}\n"
        if w.registrar:
            info += f"Registrar: {w.registrar}\n"
        return info if info else "No WHOIS info availa>
    except Exception as e:
        return f"WHOIS Error: {e}"

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK>
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except:
        pass
    return None

def scan_common_ports(ip):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, >
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_wor>
        futures = [executor.submit(scan_port, ip, port>
        for future in concurrent.futures.as_completed(>
            port = future.result()
            if port:
                open_ports.append(port)

    return


  