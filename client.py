import hashlib
import logging
import os
import socket
import threading
import time


class HashCrackingClient:
    """Connects to the server and searches the chunks it assigns."""

    def __init__(self, server_ip="127.0.0.1", port=5555, chunk_size=100000, digits=10):
        self.server_ip = server_ip
        self.port = port
        self.chunk_size = chunk_size
        self.digits = digits
        self.target = ""
        self.result = None
        self.found = threading.Event()
        self.stop = threading.Event()
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

    def search_chunk(self, start):
        """Try every number in one chunk assigned by the server."""
        for num in range(start, start + self.chunk_size):
            if self.found.is_set() or self.stop.is_set():
                return
            number = str(num).zfill(self.digits)
            if hashlib.md5(number.encode()).hexdigest() == self.target:
                self.result = number
                self.found.set()
                self.logger.info("Match found in chunk starting at %s: %s", start, number)
                return

    def receive_chunks(self):
        """Read and return start offsets from a task message."""
        count_data = self.recv_exact(self.socket, 2)
        if count_data is None:
            return None
        starts = []
        for _ in range(int(count_data)):
            start_data = self.recv_exact(self.socket, self.digits)
            if start_data is None:
                return None
            starts.append(int(start_data))
        self.logger.info("Received %s work chunk(s): %s", len(starts), starts)
        return starts

    def process_chunks(self, starts):
        """Search chunks and listen for an early stop message."""
        threads = [threading.Thread(target=self.search_chunk, args=(start,)) for start in starts]
        self.logger.info("Starting %s worker thread(s)", len(threads))
        for thread in threads:
            thread.start()

        self.socket.settimeout(0.1)
        try:
            while any(thread.is_alive() for thread in threads):
                try:
                    command = self.recv_exact(self.socket, 1)
                    if command == b"S":
                        answer = self.recv_exact(self.socket, self.digits)
                        if answer is not None:
                            self.logger.info("Server stopped the search; answer: %s", answer.decode())
                        self.stop.set()
                        break
                    if command is None:
                        self.stop.set()
                        self.logger.warning("Server disconnected while chunks were processing")
                        break
                except socket.timeout:
                    pass
        finally:
            self.socket.settimeout(None)
            for thread in threads:
                thread.join()
            self.logger.info("All worker threads finished")

    def run(self):
        """Run until a result is found or the server finishes."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((self.server_ip, self.port))
            self.logger.info("Connected to %s:%s", self.server_ip, self.port)
            target = self.recv_exact(self.socket, 32)
            if target is None:
                return
            self.target = target.decode()
            cores = min(os.cpu_count() or 1, 99)
            self.logger.info("Received target hash: %s", self.target)
            self.logger.info("Using %s CPU core(s)", cores)

            while not self.stop.is_set():
                self.socket.sendall(b"R" + f"{cores:02}".encode())
                command = self.recv_exact(self.socket, 1)
                if command == b"X" or command is None:
                    self.logger.info("Server reported that all work is complete")
                    break
                if command == b"W":
                    self.logger.info("No chunk is available yet; waiting")
                    time.sleep(0.2)
                    continue
                if command == b"S":
                    answer = self.recv_exact(self.socket, self.digits)
                    if answer is not None:
                        self.logger.info("Search stopped; answer: %s", answer.decode())
                    break
                if command != b"T":
                    raise ConnectionError("Unexpected server command")

                starts = self.receive_chunks()
                if starts is None:
                    break
                self.process_chunks(starts)
                if self.stop.is_set():
                    break
                if self.found.is_set():
                    self.socket.sendall(b"F" + self.result.encode())
                    if self.recv_exact(self.socket, 1) == b"S":
                        answer = self.recv_exact(self.socket, self.digits)
                        if answer is not None:
                            self.logger.info("Server confirmed result: %s", answer.decode())
                    break
                self.socket.sendall(b"D")
                self.logger.info("Finished assigned chunks; requesting more work")
        finally:
            self.socket.close()
            self.logger.info("Connection closed")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    HashCrackingClient().run()
