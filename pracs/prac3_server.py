import socket
import json
import time
import argparse
from collections import defaultdict

def fmt_time(ts=None):
    return time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(ts or time.time()))

def run_server(host: str, port: int, bufsize: int = 4096):
    stats = defaultdict(int)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    print(f"UDP-echo server listening on {host}:{port}")

    try:
        while True:
            # recvfrom returns (bytes, (ip, port))
            data, addr = sock.recvfrom(bufsize)
            recv_time = time.time()
            client_ip, client_port = addr[0], addr[1]

            # decode using utf-8 (handle invalid bytes gracefully)
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                text = data.decode('utf-8', errors='replace')

            stats[client_ip] += 1

            response_obj = {
                'msg_upper': text.upper(),
                'length': len(text),
                'timestamp': recv_time,
                'client_ip': client_ip,
                'total_requests_from_this_ip': stats[client_ip],
            }

            print(f"[{fmt_time(recv_time)}] Received from {client_ip}:{client_port} - {repr(text)}")
            print("  Sending:", json.dumps(response_obj, ensure_ascii=False))

            response_bytes = json.dumps(response_obj, ensure_ascii=False).encode('utf-8')
            sock.sendto(response_bytes, addr)

    except KeyboardInterrupt:
        print("\nServer shutting down (KeyboardInterrupt).")
    finally:
        sock.close()

run_server("0.0.0.0", 9999)
