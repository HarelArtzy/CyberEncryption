import logging
import socket
import threading


class HashCrackingServer:
    """Assigns number ranges and stops clients when one finds a match."""

    def __init__(self, host="0.0.0.0", port=5555, target="EC9C0F7EDCC18A98B1F31853B1813301", chunk_size=100000, digits=10):
        self.host = host
        self.port = port
        self.target = target.lower()
        self.chunk_size = chunk_size
        self.digits = digits
        self.maximum = 10 ** digits
        self.current = 0
        self.retry = []
        self.clients = {}
        self.lock = threading.Lock()
        self.finished = threading.Event()
        self.socket = None
        self.logger = logging.getLogger(self.__class__.__name__)

    def recv_exact(self, sock, size):
        """Receive exactly size bytes, or None when the peer disconnects."""
        data = b""
        while len(data) < size:
            part = sock.recv(size - len(data))
            if not part:
                return None
            data += part
        return data

    def stop_all(self, result):
        """Notify all clients that a matching value was found."""
        self.finished.set()
        with self.lock:
            client_sockets = list(self.clients)
        self.logger.info("Stopping %s client(s); result: %s", len(client_sockets), result)
        for client in client_sockets:
            try:
                client.sendall(b"S" + result.encode())
            except OSError:
                pass

    def assign_chunks(self, client, cores):
        """Reserve up to cores chunks for a client."""
        starts = []
        while self.retry and len(starts) < cores:
            starts.append(self.retry.pop())
        while len(starts) < cores and self.current < self.maximum:
            starts.append(self.current)
            self.current += self.chunk_size
        self.clients[client] = starts
        self.logger.info("Assigned %s chunk(s)", len(starts))
        return starts

    def send_task(self, client, address, starts):
        data = b"T" + f"{len(starts):02}".encode()
        for start in starts:
            data += f"{start:0{self.digits}}".encode()
        client.sendall(data)
        self.logger.info("Sent chunks to %s: %s", address, starts)

    def handle_request(self, client, address):
        command = self.recv_exact(client, 1)
        if not command:
            return False
        if command == b"R":
            cores_data = self.recv_exact(client, 2)
            if cores_data is None:
                return False
            with self.lock:
                if self.finished.is_set():
                    return False
                starts = self.assign_chunks(client, int(cores_data))
                if starts:
                    self.send_task(client, address, starts)
                elif any(self.clients.values()):
                    client.sendall(b"W")
                    self.logger.info("No work available for %s; client will wait", address)
                else:
                    client.sendall(b"X")
                    self.logger.info("No work remains; notified %s", address)
        elif command == b"D":
            with self.lock:
                self.clients[client] = []
            self.logger.info("%s completed its assigned chunks", address)
        elif command == b"F":
            result = self.recv_exact(client, self.digits)
            if result is None:
                return False
            answer = result.decode()
            self.logger.info("%s found the matching number: %s", address, answer)
            self.stop_all(answer)
            return False
        else:
            raise ConnectionError("Unexpected client command")
        return True

    def handle_client(self, client, address):
        self.logger.info("Client connected: %s", address)
        with self.lock:
            self.clients[client] = []
            client.sendall(self.target.encode())
        try:
            while not self.finished.is_set() and self.handle_request(client, address):
                pass
        except (ConnectionError, OSError, ValueError) as error:
            self.logger.error("Client error from %s: %s", address, error)
        finally:
            with self.lock:
                if not self.finished.is_set():
                    self.retry.extend(self.clients.get(client, []))
                self.clients.pop(client, None)
            client.close()
            self.logger.info("Client disconnected: %s", address)

    def run(self):
        """Accept clients until a client reports the matching number."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        self.socket.settimeout(1)
        self.logger.info("Listening on %s:%s", self.host, self.port)
        try:
            while not self.finished.is_set():
                try:
                    client, address = self.socket.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self.handle_client, args=(client, address)).start()
        finally:
            self.socket.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    target = input("Enter the target MD5 hash: ").strip()
    HashCrackingServer(target=target).run()
