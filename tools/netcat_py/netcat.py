"""
Simple Python NetCat (client/server) for Windows 11
Features:
- Client mode: connect to target:port, send stdin (or file) and print received data
- Server (listen) mode: listen on port, accept connection(s), forward data to/from client
- Save received data to file (-o) or send file (-i)

Security / usage note: This is a simple networking tool for testing and education. Use only on systems/networks you own or are authorized
to test. Avoid using it for unauthorized access.

Usage examples:
  python netcat.py example.com 1234            # connect to host:port
  python netcat.py -l -p 4444                 # listen on port 4444 (single connection)
  python netcat.py -l -p 4444 -m              # listen and accept multiple connections
  python netcat.py -l -p 4444 -o received.bin # save incoming bytes to file
  python netcat.py host 1234 -i send.bin      # send a file to host:port then exit

Author: generated helper (adapted for Windows)
"""

import socket
import threading
import argparse
import sys
import os
import time

BUFFER_SIZE = 4096


def handle_client(client_socket, addr, args):
    """Handle a single client connection (server side)."""
    print(f"[+] Connection from {addr[0]}:{addr[1]}")

    if args.output:
        # Save all incoming data to file then close
        try:
            with open(args.output, 'ab') as f:
                while True:
                    data = client_socket.recv(BUFFER_SIZE)
                    if not data:
                        break
                    f.write(data)
            print(f"[+] Saved incoming data to {args.output}")
        except Exception as e:
            print(f"[!] Error saving to file: {e}")
        finally:
            client_socket.close()
        return

    # Interactive relay: recv -> stdout, stdin -> send
    stopped = threading.Event()

    def recv_thread():
        try:
            while not stopped.is_set():
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                try:
                    # write bytes to stdout buffer
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except Exception:
                    # fallback to text write
                    try:
                        sys.stdout.write(data.decode(errors='replace'))
                        sys.stdout.flush()
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            stopped.set()

    t = threading.Thread(target=recv_thread, daemon=True)
    t.start()

    try:
        # Read from stdin and send to client
        while not stopped.is_set():
            # On Windows, sys.stdin.buffer.readline() will block until newline or EOF
            data = sys.stdin.buffer.readline()
            if not data:
                break
            client_socket.sendall(data)
    except Exception:
        pass
    finally:
        stopped.set()
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        client_socket.close()
        print("[+] Connection closed")


def server_mode(port, args):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("", port))
        srv.listen(5)
    except Exception as e:
        print(f"[!] Failed to bind/listen on port {port}: {e}")
        return

    print(f"[+] Listening on 0.0.0.0:{port}")

    try:
        while True:
            client, addr = srv.accept()
            # For single connection mode, handle in current thread
            if args.multi:
                threading.Thread(target=handle_client, args=(client, addr, args), daemon=True).start()
            else:
                handle_client(client, addr, args)
                # after connection closed, break
                if not args.multi:
                    break
    except KeyboardInterrupt:
        print("[!] Interrupted, shutting down server")
    finally:
        try:
            srv.close()
        except Exception:
            pass


def client_mode(host, port, args):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
    except Exception as e:
        print(f"[!] Failed to connect to {host}:{port}: {e}")
        return

    # If input file specified, send it and exit
    if args.input:
        try:
            with open(args.input, 'rb') as f:
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    s.sendall(chunk)
            print(f"[+] Sent file {args.input} to {host}:{port}")
        except Exception as e:
            print(f"[!] Error sending file: {e}")
        finally:
            s.close()
        return

    # Interactive: spawn thread to receive and print
    stopped = threading.Event()

    def recv_thread():
        try:
            while not stopped.is_set():
                data = s.recv(BUFFER_SIZE)
                if not data:
                    break
                try:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except Exception:
                    try:
                        sys.stdout.write(data.decode(errors='replace'))
                        sys.stdout.flush()
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            stopped.set()

    t = threading.Thread(target=recv_thread, daemon=True)
    t.start()

    try:
        while not stopped.is_set():
            data = sys.stdin.buffer.readline()
            if not data:
                break
            s.sendall(data)
    except KeyboardInterrupt:
        pass
    finally:
        stopped.set()
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        s.close()


def parse_args():
    p = argparse.ArgumentParser(description='Simple Python NetCat - client/server for Windows')
    p.add_argument('target', nargs='?', help='Target host (for client mode)')
    p.add_argument('port', nargs='?', type=int, help='Port')
    p.add_argument('-l', '--listen', action='store_true', help='Listen mode, for inbound connects')
    p.add_argument('-p', '--portnum', type=int, help='Port to listen on (alternative to positional)')
    p.add_argument('-o', '--output', help='When listening: save all incoming bytes to file')
    p.add_argument('-i', '--input', help='When connecting: read and send this file then exit')
    p.add_argument('-m', '--multi', action='store_true', help='In listen mode, accept multiple connections')
    return p.parse_args()


def main():
    args = parse_args()

    # Determine port
    port = None
    if args.port:
        try:
            port = int(args.port)
        except Exception:
            pass
    if args.portnum:
        port = args.portnum

    # If listen mode
    if args.listen:
        if not port:
            print("[!] Listen mode requires a port (use -p PORT or provide positional port)")
            return
        server_mode(port, args)
        return

    # Client mode: need target and port (either positional or portnum)
    if not args.target or not port:
        print("[!] For client mode you must provide target and port (e.g. host 1234)")
        return

    client_mode(args.target, port, args)


if __name__ == '__main__':
    main()
