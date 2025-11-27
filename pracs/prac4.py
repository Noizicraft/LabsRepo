#!/usr/bin/env python3
import socket
import struct
import time
import select
import os


def checksum(data):
    """Вычисление контрольной суммы ICMP пакета по RFC 1071"""
    if len(data) % 2:
        data += b'\x00'  # Добавляем нулевой байт если длина нечётная
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))  # Суммируем 16-битные слова
    s = (s >> 16) + (s & 0xffff)  # Складываем старшую и младшую части
    s += s >> 16  # Добавляем возможный перенос
    return ~s & 0xffff  # Побитовое НЕ и маска до 16 бит


def create_icmp_packet(packet_id, seq, payload_size=56):
    """Создание ICMP Echo Request пакета"""
    # Заголовок ICMP: тип(1), код(1), контрольная сумма(2), ID(2), номер последовательности(2)
    header = struct.pack('!BBHHH', 8, 0, 0, packet_id, seq)  # type=8 (Echo Request)

    # Полезная нагрузка: временная метка + заполнение
    stamp = struct.pack('!d', time.time())  # Текущее время для измерения RTT
    payload = stamp + (b'Q' * (payload_size - len(stamp)))  # Заполняем оставшееся пространство

    # Вычисляем и устанавливаем контрольную сумму
    chk = checksum(header + payload)
    header = struct.pack('!BBHHH', 8, 0, chk, packet_id, seq)

    return header + payload


def parse_icmp_reply(packet, expected_id):
    """Разбор ICMP Echo Reply пакета"""
    if len(packet) < 20:
        return None

    # Извлекаем длину IP-заголовка (первые 4 бита первого байта)
    ip_header_len = (packet[0] & 0x0F) * 4

    # Проверяем что пакет достаточно длинный
    if len(packet) < ip_header_len + 16:  # IP заголовок + ICMP заголовок + timestamp
        return None

    # Извлекаем ICMP часть пакета (после IP заголовка)
    icmp = packet[ip_header_len:]

    # Разбираем ICMP заголовок
    icmp_type, icmp_code, _, recv_id, seq = struct.unpack('!BBHHH', icmp[:8])

    # Проверяем что это Echo Reply с правильным ID
    if icmp_type == 0 and icmp_code == 0 and recv_id == expected_id:
        sent_time = struct.unpack('!d', icmp[8:16])[0]  # Извлекаем исходное время отправки
        rtt = (time.time() - sent_time) * 1000.0  # Вычисляем время кругового пути в мс
        return seq, rtt, len(icmp)

    return None


def run_ping(dest_host, count=4, timeout=1.0, payload_size=56, interval=1.0):
    """Основная функция выполнения ping"""
    try:
        dest_ip = socket.gethostbyname(dest_host)  # Разрешение доменного имени в IP
    except socket.gaierror as e:
        print(f"Не могу разрешить адрес {dest_host}: {e}")
        return

    print(f"PING {dest_host} ({dest_ip}) {payload_size}({payload_size + 28}) bytes of data.")

    try:
        # Создаём raw socket для отправки/приёма ICMP пакетов
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Ошибка: требуется запуск от root.")  # Raw sockets требуют прав root
        return

    sock.setblocking(False)  # Неблокирующий режим для использования select
    pid = os.getpid() & 0xFFFF  # ID процесса как идентификатор пакетов
    transmitted = received = 0
    rtts = []  # Для хранения времени отклика

    try:
        for seq in range(1, count + 1):
            # Создаём и отправляем ICMP пакет
            packet = create_icmp_packet(pid, seq, payload_size)
            send_time = time.time()
            sock.sendto(packet, (dest_ip, 0))
            transmitted += 1

            # Ожидаем ответ с использованием select
            ready = select.select([sock], [], [], timeout)
            if ready[0]:
                # Получен ответ
                recv_packet, addr = sock.recvfrom(1024)
                parsed = parse_icmp_reply(recv_packet, pid)
                if parsed:
                    recv_seq, rtt, icmp_len = parsed
                    received += 1
                    rtts.append(rtt)
                    print(f"{icmp_len} bytes from {addr[0]}: icmp_seq={recv_seq} time={rtt:.2f} ms")
            else:
                # Таймаут - ответ не получен
                print(f"Request timeout for icmp_seq {seq}")

            # Выдерживаем интервал между запросами
            to_sleep = interval - (time.time() - send_time)
            if to_sleep > 0:
                time.sleep(to_sleep)

    except KeyboardInterrupt:
        print("\nПрервано пользователем.")
    finally:
        sock.close()

    # Вывод статистики
    loss = ((transmitted - received) / transmitted * 100) if transmitted else 0
    print(f"\n--- {dest_host} ping statistics ---")
    print(f"{transmitted} packets transmitted, {received} received, {loss:.0f}% packet loss")
    if rtts:
        avg = sum(rtts) / len(rtts)
        print(f"round-trip min/avg/max = {min(rtts):.2f}/{avg:.2f}/{max(rtts):.2f} ms")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('host')  # Обязательный параметр - хост
    parser.add_argument('-c', '--count', type=int, default=4)  # Количество пакетов
    parser.add_argument('-t', '--timeout', type=float, default=1.0)  # Таймаут ожидания
    parser.add_argument('--size', type=int, default=56)  # Размер полезной нагрузки
    parser.add_argument('-i', '--interval', type=float, default=1.0)  # Интервал между пакетами
    args = parser.parse_args()
    run_ping(args.host, args.count, args.timeout, args.size, args.interval)