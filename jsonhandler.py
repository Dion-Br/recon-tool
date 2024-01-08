import json
import ipaddress 
import re 

def is_valid_ip_or_domain(input_str):
    try:
        ipaddress.ip_address(input_str)
        return True
    except ValueError:
        domain_regex = re.compile(
            r"^(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.?)+[A-Za-z]{2,}$"
        )
        return bool(domain_regex.match(input_str))

def add_ip_to_json(ip):
    # Kijken of het een geldig ip adres of website is
    if is_valid_ip_or_domain(ip):
        # json file inlezen
        try:
            with open("ip_addresses.json", "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            # File aanmaken bij eerste gebruik
            data = []

        # Duplicate controle
        if ip not in data:
            data.append(ip)
            with open("ip_addresses.json", "w") as file:
                json.dump(data, file)
            return True
        else:
            return False
    else:
        return False

def delete_ip_from_json(ip):
    # json file inlezen
    try:
        with open("ip_addresses.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        return

    if ip in data:
        # Gegeven ip adress verwijderen
        data.remove(ip)

        # File updaten
        with open("ip_addresses.json", "w") as file:
            json.dump(data, file)

def read_all_ips_from_json():
    # Alle data inlezen
    try:
        with open("ip_addresses.json", "r") as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        return []