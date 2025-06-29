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
            created = w.creation_date[0] if isinstance(w.creation_date, list) else w.crea>
            info += f"Creation Date: {created}\n"
        if w.expiration_date:
            expires = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.>
            info += f"Expiration Date: {expires}\n"
        if w.registrar:
            info += f"Registrar: {w.registrar}\n"
        return info if info else "No WHOIS info available"
    except Exception as e:
        return f"WHOIS Error: {e}"

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except:
        pass
    return None

def scan_common_ports(ip):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in common_ports]
        for future in concurrent.futures.as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)

    return sorted(open_ports)

def main():
    print("\033[1;36m" + "Website IP Finder Tool (Termux)" + "\033[0m")
    print("\033[1;32m" + "Created by CASREV" + "\033[0m")
    print("=" * 40)

    website = input("Enter Website (e.g., google.com): ").strip()

    if not website:
        print("\033[1;31m[!] Please enter a valid website.\033[0m")
        return

    print("\n\033[1;33m[*] Resolving IP...\033[0m")

    ip = get_ip(website)

    if ip.startswith("Error"):
        print(f"\033[1;31m[!] {ip}\033[0m")
    else:
        print(f"\033[1;32m[+] IP of {website}: \033[1;34m{ip}\033[0m")
        print(f"\033[1;35m[*] Time: {datetime.now()}\033[0m")

        # WHOIS bilgileri
        print("\n\033[1;33m[*] Getting WHOIS info...\033[0m")
        whois_info = get_whois_info(website)
        print("\033[1;37mWHOIS Information:\033[0m")
        print(whois_info)

        
        # Port tarama
        print("\n\033[1;33m[*] Scanning common ports...\033[0m")
        open_ports = scan_common_ports(ip)
        if open_ports:
            print("\033[1;32m[+] Open ports:\033[0m", ", ".join(map(str, open_ports)))
        else:
            print("\033[1;31m[!] No common ports open or all filtered\033[0m")

if __name__ == "__main__":
    main()
