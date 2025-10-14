import socket
import threading
import sys
import timef
import json
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
import webbrowser
import os
import traceback

QUIT_CMD = "/quit"
stop_event = threading.Event()


class MessageBridge:
    def __init__(self):
        self.messages = []
        self.max_messages = 1000
        # Добавляем начальное сообщение
        self.add_message("Чат инициализирован. Ожидание подключения...", "info")

    def add_message(self, text, message_type="message"):
        message = {
            'text': text,
            'timestamp': datetime.now().isoformat(),
            'type': message_type
        }
        self.messages.append(message)

        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]

    def get_messages_json(self):
        try:
            return json.dumps(self.messages, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[JSON ERROR] Ошибка сериализации: {e}")
            return json.dumps([{"text": "Ошибка формата сообщений", "type": "error"}])


# Глобальные переменные
message_bridge = MessageBridge()
tcp_socket = None
is_tcp_connected = False


class ChatHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.base_directory = os.path.dirname(os.path.abspath(__file__))
        super().__init__(*args, directory=self.base_directory, **kwargs)

    def log_message(self, format, *args):
        if self.path.startswith('/messages'):
            return  # Не логируем частые запросы messages
        print(f"[HTTP] {self.path} - {self.client_address[0]}")

    def do_GET(self):
        if self.path.startswith('/messages'):
            try:

                self.send_response(200)
                self.send_header('Content-type', 'application/json; charset=utf-8')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()

                response_data = message_bridge.get_messages_json()

                self.wfile.write(response_data.encode('utf-8'))
                return

            except Exception as e:
                print(f"[HTTP ERROR] Ошибка при отправке сообщений: {e}")
                self.send_error(500, f"Internal server error: {e}")
                return

        elif self.path == '/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            status = {
                'connected': is_tcp_connected,
                'message_count': len(message_bridge.messages),
                'timestamp': datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(status).encode('utf-8'))
            return

        elif self.path == '/' or self.path == '/index.html':
            try:
                file_path = 'index.html'
                full_path = os.path.join(self.base_directory, file_path)

                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()

                with open(full_path, 'rb') as file:
                    self.wfile.write(file.read())

                print(f"[HTTP] index.html отправлен")
                return

            except Exception as e:
                print(f"[HTTP ERROR] Ошибка при чтении index.html: {e}")
                self.send_error(500, f"Error reading file: {e}")
                return

        try:
            return super().do_GET()
        except Exception as e:
            print(f"[HTTP ERROR] Ошибка: {e}")
            self.send_error(404, f"File not found: {self.path}")

    def do_POST(self):
        if self.path == '/send':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')
                print(f"[HTTP] Получено сообщение: '{post_data}'")

                response = {'status': 'ok'}

                if is_tcp_connected and tcp_socket:
                    try:
                        tcp_socket.sendall((post_data + "\n").encode("utf-8"))
                        message_bridge.add_message(f"Вы: {post_data}", "user")
                        print(f"[TCP] Сообщение отправлено")
                    except Exception as e:
                        error_msg = f"Ошибка отправки: {e}"
                        response = {'status': 'error', 'message': error_msg}
                        message_bridge.add_message("Ошибка отправки", "error")
                else:
                    error_msg = 'Нет подключения к серверу'
                    response = {'status': 'error', 'message': error_msg}
                    message_bridge.add_message("Нет подключения к серверу", "error")

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return

            except Exception as e:
                print(f"[HTTP ERROR] Ошибка обработки POST: {e}")
                self.send_error(500, f"Internal server error: {e}")
                return

        self.send_response(404)
        self.end_headers()


def start_http_server(port=8000):
    def run_server():
        try:
            server = HTTPServer(('localhost', port), ChatHTTPHandler)
            print(f"✓ HTTP сервер запущен: http://localhost:{port}")
            server.serve_forever()
        except Exception as e:
            print(f"[HTTP ERROR] Ошибка сервера: {e}")

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    return server_thread


def connect_to_tcp_server(host, port):
    global tcp_socket, is_tcp_connected

    try:
        print(f"[TCP] Подключение к {host}:{port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        sock.settimeout(1.0)

        tcp_socket = sock
        is_tcp_connected = True

        print(f"✓ Подключено к TCP серверу")
        message_bridge.add_message(f"✓ Подключено к серверу {host}:{port}", "info")
        return sock

    except Exception as e:
        print(f"✗ Ошибка подключения: {e}")
        message_bridge.add_message(f"✗ Ошибка подключения: {e}", "error")
        return None


def tcp_receiver(sock):
    global is_tcp_connected

    print(f"[TCP] Приемник запущен")

    while not stop_event.is_set() and is_tcp_connected:
        try:
            data = sock.recv(4096)
            if not data:
                print("[TCP] Сервер закрыл соединение")
                message_bridge.add_message("Сервер закрыл соединение", "error")
                break

            text = data.decode("utf-8", errors="replace").strip()
            if text:
                print(f"[TCP] Получено: '{text}'")
                message_bridge.add_message(text, "message")

        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"[TCP ERROR] Ошибка: {e}")
            break

    is_tcp_connected = False
    stop_event.set()


def console_sender(sock):
    print(f"[CONSOLE] Отправитель запущен")

    while not stop_event.is_set() and is_tcp_connected:
        try:
            msg = input()
            if not msg.strip():
                continue

            if msg.strip() == QUIT_CMD:
                sock.sendall((QUIT_CMD + "\n").encode("utf-8"))
                break

            sock.sendall((msg + "\n").encode("utf-8"))
            message_bridge.add_message(f"Вы: {msg}", "user")

        except (EOFError, KeyboardInterrupt):
            break
        except Exception as e:
            print(f"[CONSOLE ERROR] Ошибка: {e}")
            break


def main():
    global is_tcp_connected

    print("=" * 50)
    print("ЗАПУСК ЧАТ-КЛИЕНТА")
    print("=" * 50)

    # Запуск HTTP сервера
    start_http_server(8000)
    time.sleep(1)

    # Подключение к TCP серверу
    host = '91.132.57.66'
    port = 2077

    sock = connect_to_tcp_server(host, port)

    if sock:
        receiver_thread = threading.Thread(target=tcp_receiver, args=(sock,), daemon=True)
        sender_thread = threading.Thread(target=console_sender, args=(sock,), daemon=True)
        receiver_thread.start()
        sender_thread.start()

    # Открываем браузер
    try:
        webbrowser.open('http://localhost:8000')
        print("✓ Браузер открыт: http://localhost:8000")
    except:
        print("✗ Откройте http://localhost:8000 вручную")

    print("\nУправление:")
    print("- Сообщения в консоль или на сайте")
    print("- Ctrl+C для выхода")
    print("=" * 50)

    try:
        while not stop_event.is_set():
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nЗавершение работы...")
    finally:
        stop_event.set()
        if sock:
            try:
                sock.close()
            except:
                pass
        print("Клиент остановлен")


if __name__ == "__main__":
    main()