#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys
import re
import shlex
import getpass
from pathlib import Path


class SimpleFTPClient:
    def __init__(self):
        self.sock = None
        self.file = None
        self.host = None
        self.port = None

    # ---------- низкий уровень ----------

    def is_connected(self):
        return self.sock is not None

    def _send_line(self, line):
        if not self.is_connected():
            raise RuntimeError("Not connected")
        data = (line + "\r\n").encode("utf-8")
        print("C:", line)
        self.file.write(data)
        self.file.flush()

    def _read_response(self):
        if not self.is_connected():
            raise RuntimeError("Not connected")
        line_bytes = self.file.readline()
        if not line_bytes:
            raise ConnectionError("Connection closed by server")
        line = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
        print("S:", line)
        code = None
        msg = ""
        if len(line) >= 3 and line[:3].isdigit():
            code = int(line[:3])
            if len(line) > 4:
                msg = line[4:]
        return code, msg, line

    def close(self):
        if self.file is not None:
            try:
                self.file.close()
            except Exception:
                pass
            self.file = None
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    # ---------- базовые команды ----------

    def connect(self, host, port=21):
        self.close()
        self.host = host
        self.port = port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        self.sock = s
        self.file = s.makefile("rwb")
        # приветствие 220
        self._read_response()

    def login(self, user, password=None):
        if not self.is_connected():
            print("Сначала выполните команду connect.")
            return
        if password is None:
            password = getpass.getpass("Пароль: ")
        self._send_line("USER {}".format(user))
        code, msg, _ = self._read_response()
        if code == 230:
            # уже залогинен без пароля
            return
        if code != 331:
            print("Неожиданный ответ на USER:", code, msg)
            return
        self._send_line("PASS {}".format(password))
        self._read_response()

    def simple_cmd(self, cmd, *args):
        if not self.is_connected():
            print("Нет активного соединения.")
            return
        line = cmd if not args else "{} {}".format(cmd, " ".join(args))
        self._send_line(line)
        self._read_response()

    # ---------- пассивный режим и data-канал ----------

    def _enter_passive(self):
        # Открыть PASV и вернуть уже подключённый data-socket
        if not self.is_connected():
            print("Нет активного соединения.")
            return None
        self._send_line("PASV")
        code, msg, line = self._read_response()
        if code != 227:
            print("PASV не поддерживается или ошибка:", line)
            return None
        m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", line)
        if not m:
            print("Не удалось разобрать ответ PASV:", line)
            return None
        h1, h2, h3, h4, p1, p2 = map(int, m.groups())
        ip = "%d.%d.%d.%d" % (h1, h2, h3, h4)
        port = p1 * 256 + p2
        data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_sock.connect((ip, port))
        return data_sock

    # ---------- LIST / RETR / STOR ----------

    def list(self):
        if not self.is_connected():
            print("Нет активного соединения.")
            return
        data_sock = self._enter_passive()
        if data_sock is None:
            return
        self._send_line("LIST")
        code, msg, line = self._read_response()
        if code != 150:
            print("Сервер отклонил LIST:", line)
            data_sock.close()
            return
        try:
            while True:
                chunk = data_sock.recv(4096)
                if not chunk:
                    break
                sys.stdout.write(chunk.decode("utf-8", errors="replace"))
            sys.stdout.flush()
        finally:
            data_sock.close()
        # завершающий ответ 226
        self._read_response()

    def retr(self, remote_name, local_name=None):
        if not self.is_connected():
            print("Нет активного соединения.")
            return
        if not remote_name:
            print("Укажите имя файла на сервере.")
            return
        if local_name is None:
            local_name = remote_name
        data_sock = self._enter_passive()
        if data_sock is None:
            return
        self._send_line("RETR {}".format(remote_name))
        code, msg, line = self._read_response()
        if code != 150:
            print("Сервер отклонил RETR:", line)
            data_sock.close()
            return
        try:
            with open(local_name, "wb") as f:
                while True:
                    chunk = data_sock.recv(4096)
                    if not chunk:
                        break
                    f.write(chunk)
            print("Файл сохранён как {}".format(local_name))
        finally:
            data_sock.close()
        self._read_response()

    def stor(self, local_name, remote_name=None):
        if not self.is_connected():
            print("Нет активного соединения.")
            return
        path = Path(local_name)
        if not path.is_file():
            print("Локальный файл не найден: {}".format(local_name))
            return
        if remote_name is None:
            remote_name = path.name
        data_sock = self._enter_passive()
        if data_sock is None:
            return
        self._send_line("STOR {}".format(remote_name))
        code, msg, line = self._read_response()
        if code != 150:
            print("Сервер отклонил STOR:", line)
            data_sock.close()
            return
        try:
            with path.open("rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    data_sock.sendall(chunk)
        finally:
            data_sock.close()
        self._read_response()

    # ---------- доп. команды (варианты) ----------

    def rename(self, old, new):
        if not self.is_connected():
            print("Нет активного соединения.")
            return
        if not old or not new:
            print("Использование: rename <старое_имя> <новое_имя>")
            return
        self._send_line("RNFR {}".format(old))
        code, msg, line = self._read_response()
        if code != 350:
            print("Ошибка RNFR:", line)
            return
        self._send_line("RNTO {}".format(new))
        self._read_response()

    def quit(self):
        if not self.is_connected():
            return
        try:
            self._send_line("QUIT")
            self._read_response()
        except Exception:
            pass
        self.close()


def print_help():
    print("""Доступные команды:
  connect <host> [port]    - соединиться с FTP-сервером
  login <user> [password]  - аутентификация (если пароль не задан, будет запрошен)
  pwd                      - показать текущий каталог на сервере
  cwd <path>               - сменить каталог на сервере
  list                     - список файлов/каталогов (LIST через PASV)
  retr <remote> [local]    - скачать файл с сервера
  stor <local> [remote]    - загрузить файл на сервер
  delete <name>            - удалить файл (DELE)
  mkdir <dirname>          - создать каталог (MKD)
  rename <old> <new>       - переименовать файл/каталог (RNFR/RNTO)
  quit / exit              - завершить работу клиента
  help                     - показать эту справку
""")


def repl():
    client = SimpleFTPClient()
    print_help()
    while True:
        try:
            line = input("ftp> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line.strip():
            continue
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print("Ошибка разбора команды:", e)
            continue
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "connect":
            if len(args) < 1:
                print("Использование: connect <host> [port]")
                continue
            host = args[0]
            port = int(args[1]) if len(args) >= 2 else 21
            try:
                client.connect(host, port)
            except Exception as e:
                print("Ошибка подключения:", e)

        elif cmd == "login":
            if len(args) == 0:
                print("Использование: login <user> [password]")
                continue
            user = args[0]
            password = args[1] if len(args) >= 2 else None
            client.login(user, password)

        elif cmd == "pwd":
            client.simple_cmd("PWD")

        elif cmd == "cwd":
            if len(args) != 1:
                print("Использование: cwd <path>")
                continue
            client.simple_cmd("CWD", args[0])

        elif cmd == "list":
            client.list()

        elif cmd == "retr":
            if len(args) == 0:
                print("Использование: retr <remote> [local]")
                continue
            remote = args[0]
            local = args[1] if len(args) >= 2 else None
            client.retr(remote, local)

        elif cmd == "stor":
            if len(args) == 0:
                print("Использование: stor <local> [remote]")
                continue
            local = args[0]
            remote = args[1] if len(args) >= 2 else None
            client.stor(local, remote)

        elif cmd == "delete":
            if len(args) != 1:
                print("Использование: delete <name>")
                continue
            client.simple_cmd("DELE", args[0])

        elif cmd == "mkdir":
            if len(args) != 1:
                print("Использование: mkdir <dirname>")
                continue
            client.simple_cmd("MKD", args[0])

        elif cmd == "rename":
            if len(args) != 2:
                print("Использование: rename <old> <new>")
                continue
            client.rename(args[0], args[1])

        elif cmd in ("quit", "exit"):
            client.quit()
            break

        elif cmd == "help":
            print_help()

        else:
            print("Неизвестная команда. Введите help для списка.")

    client.close()


if __name__ == "__main__":
    repl()
