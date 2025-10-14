import ipaddress


def check_suspicious_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "Невалидный IP-адрес"
    if ip in ipaddress.ip_network("10.0.0.0/8"):
        return "RFC 1918 - Приватная сеть"
    elif ip in ipaddress.ip_network("172.16.0.0/12"):
        return "RFC 1918 - Приватная сеть"
    elif ip in ipaddress.ip_network("192.168.0.0/16"):
        return "RFC 1918 - Приватная сеть"
    elif ip in ipaddress.ip_network("127.0.0.0/8"):
        return "RFC 5735 - Loopback"
    elif ip in ipaddress.ip_network("169.254.0.0/16"):
        return "RFC 3927 - Link-local"
    elif ip in ipaddress.ip_network("224.0.0.0/4"):
        return "RFC 5771 - Multicast"
    elif ip in ipaddress.ip_network("240.0.0.0/4"):
        return "Зарезервировано"
    else:
        return "Публичный IP-адрес"


# Пример использования
if __name__ == "__main__":
    test_ips = ["192.168.1.1", "8.8.8.8", "127.0.0.1", "169.254.1.1"]

    for ip in test_ips:
        result = check_suspicious_ip(ip)
        print(f"{ip}: {result}")