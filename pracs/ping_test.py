#!/usr/bin/env python3
# ping_raw.py — упрощённая реализация ping через raw sockets
# Запуск: sudo python3 ping_raw.py <host> [-c COUNT] [-t TIMEOUT] [--size PAYLOAD]
#
# Требует прав суперпользователя (root).

import socket
import struct
import time
import select
import sys
import argparse
import os

def checksum(data: bytes) -> int:
    # RFC 1071: складываем 16-битные слова, производим "folding", затем побитовое НЕ
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_icmp_packet(packet_id: int, seq: int, payload_size: int = 56) -> bytes:
    # ICMP header: type (1), code (1), checksum (2), id (2), seq (2)
    header = struct.pack('!BBHHH', 8, 0, 0, packet_id, seq)  # type=8 (Echo Request), code=0, checksum=0 placeholder
    # payload: first 8 bytes — timestamp (double network order), rest — padding
    stamp = struct.pack('!d', time.time())
    pad_len = max(0, payload_size - len(stamp))
    payload = stamp + (b'Q' * pad_len)
    chk = checksum(header + payload)
    header = struct.pack('!BBHHH', 8, 0, chk, packet_id, seq)
    return header + payload

def parse_icmp_reply(packet: bytes, expected_id: int):
    # Отбрасываем IP-заголовок (определяем длину из первого байта)
    if len(packet) < 20:
        return None
    ip_header_len = (packet[0] & 0x0F) * 4
    if len(packet) < ip_header_len + 8 + 8:
        return None
    icmp = packet[ip_header_len:]
    icmp_type, icmp_code, _, recv_id, seq = struct.unpack('!BBHHH', icmp[:8])
    if icmp_type == 0 and icmp_code == 0 and recv_id == expected_id:
        # извлекаем временную метку (8 байт) из payload
        try:
            sent_time = struct.unpack('!d', icmp[8:16])[0]
        except struct.error:
            return None
        rtt = (time.time() - sent_time) * 1000.0  # ms
        return seq, rtt, len(icmp)
    return None

def run_ping(dest_host: str, count: int = 4, timeout: float = 1.0, payload_size: int = 56, interval: float = 1.0):
    try:
        dest_ip = socket.gethostbyname(dest_host)
    except socket.gaierror as e:
        print(f"Не могу разрешить адрес {dest_host}: {e}")
        return

    print(f"PING {dest_host} ({dest_ip}) {payload_size}({payload_size + 28}) bytes of data.")  # +28 = IP(20)+ICMP(8)

    # raw socket для ICMP
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Ошибка: требуется запуск от root (пользователь с правами суперпользователя).")
        return

    sock.setblocking(False)
    pid = os.getpid() & 0xFFFF
    transmitted = 0
    received = 0
    rtts = []

    seq = 1
    try:
        while count == 0 or seq <= count:
            packet = create_icmp_packet(pid, seq, payload_size=payload_size)
            send_time = time.time()
            try:
                sock.sendto(packet, (dest_ip, 0))
            except Exception as e:
                print(f"Ошибка при отправке пакета: {e}")
                break
            transmitted += 1

            # ожидание ответа с select
            start_wait = time.time()
            ready = select.select([sock], [], [], timeout)
            if ready[0]:
                recv_packet, addr = sock.recvfrom(65535)
                parsed = parse_icmp_reply(recv_packet, pid)
                if parsed:
                    recv_seq, rtt, icmp_len = parsed
                    received += 1
                    rtts.append(rtt)
                    # Обычно показывают 64 bytes (ICMP header 8 + payload 56)
                    print(f"{icmp_len} bytes from {addr[0]}: icmp_seq={recv_seq} time={rtt:.2f} ms")
                else:
                    # Пришел пакет, но не тот, что ожидали (или другой ID) — игнорируем
                    # Подождём остаток таймаута, чтобы попытаться получить корректный ответ
                    # (упрощённо — считаем как потеря)
                    print("Получен неожиданный или некорректный ICMP-пакет — игнорируется.")
            else:
                print(f"Request timeout for icmp_seq {seq}")

            seq += 1
            # интервал между посылками
            to_sleep = interval - (time.time() - send_time)
            if to_sleep > 0:
                time.sleep(to_sleep)
    except KeyboardInterrupt:
        print("\nПрервано пользователем.")
    finally:
        sock.close()

    # статистика
    loss = ((transmitted - received) / transmitted * 100) if transmitted else 0
    print(f"\n--- {dest_host} ping statistics ---")
    print(f"{transmitted} packets transmitted, {received} received, {loss:.0f}% packet loss")
    if rtts:
        print("round-trip min/avg/max = {:.2f}/{:.2f}/{:.2f} ms".format(min(rtts), sum(rtts)/len(rtts), max(rtts)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Упрощённая реализация ping (ICMP Echo) через raw-сокеты.")
    parser.add_argument('host', help='Хост или IP-адрес для ping')
    parser.add_argument('-c', '--count', type=int, default=4, help='Количество пакетов (0 = бесконечно), по умолчанию 4')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Таймаут в секундах на ответ (по умолчанию 1.0)')
    parser.add_argument('--size', type=int, default=56, help='Размер полезной нагрузки в байтах (по умолчанию 56)')
    parser.add_argument('-i', '--interval', type=float, default=1.0, help='Интервал между пакетами в секундах (по умолчанию 1.0)')
    args = parser.parse_args()
    run_ping(args.host, count=args.count, timeout=args.timeout, payload_size=args.size, interval=args.interval)
