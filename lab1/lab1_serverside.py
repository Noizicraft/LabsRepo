#!/usr/bin/env python3
# coding: utf-8
"""
Simple multithreaded TCP chat server.
Usage: python chat_server.py [host] [port]
Client examples: `telnet localhost 9000` or `nc localhost 9000`
Command for client to exit gracefully: /quit
"""

import socket
import threading
import sys

# Command for exit
QUIT_CMD = "/quit"

# Structure for storing connections:
# list of dictionaries: {"sock": socket, "addr": (ip,port), "name": "ip:port"}
clients = []
clients_lock = threading.Lock()


def addr_to_name(addr):
    return f"{addr[0]}:{addr[1]}"


def broadcast(message: str, exclude_sock: socket.socket = None):
    """Send message to all connected clients, except exclude_sock (if specified)."""
    with clients_lock:
        dead = []
        for c in clients:
            s = c["sock"]
            if s is exclude_sock:
                continue
            try:
                s.sendall(message.encode("utf-8"))
            except Exception:
                # mark socket for removal
                dead.append(c)
        # remove dead clients
        for d in dead:
            try:
                d["sock"].close()
            except Exception:
                pass
            if d in clients:
                clients.remove(d)


def handle_client(client_sock: socket.socket, client_addr):
    """Thread handler for a single client."""
    name = addr_to_name(client_addr)
    # add client to the shared list
    with clients_lock:
        clients.append({"sock": client_sock, "addr": client_addr, "name": name})

    print(f"New connection: {name}")  # item 1.5 - output in main thread (here in accept thread we also print)
    try:
        # send welcome message to client
        try:
            client_sock.sendall(f"Welcome to the chat. To exit, type {QUIT_CMD}\n".encode("utf-8"))
        except Exception:
            pass

        buffer = b""
        while True:
            try:
                data = client_sock.recv(4096)
            except ConnectionResetError:
                data = b""
            if not data:
                # client closed connection
                print(f"Client {name} disconnected (connection closed).")
                break

            buffer += data
            # process by lines - separator '\n'
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                try:
                    text = line.decode("utf-8").strip()
                except Exception:
                    text = line.decode("utf-8", errors="replace").strip()

                if not text:
                    continue

                # if client wants to exit
                if text == QUIT_CMD:
                    try:
                        client_sock.sendall("You have been disconnected. Goodbye.\n".encode("utf-8"))
                    except Exception:
                        pass
                    print(f"Client {name} disconnected via {QUIT_CMD} command.")
                    # notify others that client left (optional)
                    broadcast(f"[{name}] left the chat.\n", exclude_sock=client_sock)
                    raise SystemExit  # exit client handling
                else:
                    # format: [ADDR:PORT_CLIENT]> Message
                    out = f"[{name}]> {text}\n"
                    print(f"Message from {name}: {text}")
                    broadcast(out, exclude_sock=client_sock)

    except SystemExit:
        pass
    except Exception as e:
        print(f"Error with client {name}: {e}")
    finally:
        # close socket and remove from list
        try:
            client_sock.close()
        except Exception:
            pass
        with clients_lock:
            # find entry by socket and remove
            for c in clients:
                if c["sock"] is client_sock:
                    clients.remove(c)
                    break
        print(f"Connection with {name} closed and removed from active list.")


def start_server(host: str = "0.0.0.0", port: int = 9000):
    """Start server and accept connections."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    print(f"Server started and listening on {host}:{port}")
    try:
        while True:
            try:
                client_sock, client_addr = srv.accept()
            except KeyboardInterrupt:
                raise
            # connection log in main thread (item 1.5)
            print(f"Accepted connection from {addr_to_name(client_addr)}")
            # create thread for client
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nServer stopping (KeyboardInterrupt). Closing connections...")
    finally:
        # close all client sockets
        with clients_lock:
            for c in clients:
                try:
                    c["sock"].close()
                except Exception:
                    pass
            clients.clear()
        try:
            srv.close()
        except Exception:
            pass
        print("Server properly terminated.")


if __name__ == "__main__":
    host = "0.0.0.0"
    port = 2077
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Invalid port, using 9000")
            port = 2077
    start_server(host, port)