import socket
import select

def connect_to_server(host='', port=8080):
    try:
        # Создаем сокет
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10.0)
        # Подключаемся к серверу
        client_socket.connect((host, port))
        print(f"Connected to server {host}:{port}")
        try:
            while True:
                # Читаем ввод пользователя
                message = input("Enter message to send (or 'quit' to exit): ")

                if message.lower() == 'quit':
                    break

                # Отправляем сообщение
                client_socket.sendall((message + '\0').encode())
                print(f"Sent: {message}")

                # Ожидаем ответ от сервера с таймаутом
                response = receive_data(client_socket, timeout=5.0)
                if response:
                    print(f"Server response: {response}")
                else:
                    print("No response received from server within timeout")

        except KeyboardInterrupt:
            print("\nClient interrupted by user")
        finally:
            client_socket.close()
            print("Connection closed")

    except Exception as e:
        print(f"Error: {e}")

def receive_data(sock, timeout=5.0):
    """Получает данные от сервера с таймаутом"""
    sock.settimeout(timeout)
    try:
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b'\0' in chunk:
                break
        return data.decode('utf-8').rstrip('\0') if data else None
    except socket.timeout:
        return None
    except Exception as e:
        print(f"Receive error: {e}")
        return None

if __name__ == "__main__":
    connect_to_server('91.132.57.66', 7777)