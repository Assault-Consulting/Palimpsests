"""Raw TCP tee-proxy: 127.0.0.1:11437 -> 127.0.0.1:11436.
Logs client->server bytes (requests+bodies) to proxy_req.log and
server->client bytes (responses+SSE bodies) to proxy_resp.log, verbatim.
Byte passthrough — handles streaming/SSE without HTTP parsing. Does not touch
the operator's serve (11435) or the diag serve internals (11436)."""
import socket
import threading

LISTEN = ("127.0.0.1", 11437)
UP = ("127.0.0.1", 11436)
REQ = open("proxy_req.log", "ab")
RESP = open("proxy_resp.log", "ab")
LOCK = threading.Lock()


def pipe(src, dst, log, marker):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            with LOCK:
                log.write(marker + b" " + data)
                log.flush()
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client):
    try:
        up = socket.create_connection(UP)
    except OSError:
        client.close()
        return
    sep = b"\n===CONN===\n"
    with LOCK:
        REQ.write(sep); REQ.flush(); RESP.write(sep); RESP.flush()
    t1 = threading.Thread(target=pipe, args=(client, up, REQ, b"[REQ]"))
    t2 = threading.Thread(target=pipe, args=(up, client, RESP, b"[RESP]"))
    t1.start(); t2.start(); t1.join(); t2.join()
    client.close(); up.close()


def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(LISTEN)
    s.listen(50)
    print("tee-proxy listening on", LISTEN, "-> upstream", UP, flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
