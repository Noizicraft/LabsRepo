import socket
import json


def simple_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5.0)

    srv_addr = ('91.132.57.66', 9999)

    try:
        while True:
            msg = input("Введите сообщение: ")

            # Отправляем сообщение
            client_socket.sendto(msg.encode('utf-8'), srv_addr)

            try:
                # Получаем ответ
                response, _ = client_socket.recvfrom(4096)

                # Парсим JSON-ответ
                data = json.loads(response.decode('utf-8'))

                print("Ответ от сервера:")
                print(json.dumps(data, indent=2, ensure_ascii=False))
                print()
            except socket.timeout:
                print("Ответ от сервера не получен (таймаут)\n")
            except ConnectionResetError:
                print("Соединение разорвано сервером\n")
            except Exception as e:
                print(f"Ошибка при получении ответа: {e}\n")

    except KeyboardInterrupt:
        print("\nВыход...")
    finally:
        client_socket.close()


if __name__ == "__main__":
    simple_client()