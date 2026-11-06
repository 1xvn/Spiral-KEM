"""Single-owner framed I/O around the record state; no automatic request retry."""
import threading
import time
from contextlib import contextmanager

from .records import RecordState, RecordLimit, DATA, CLOSE
from .wire import ProtocolError


class Channel:
    def __init__(self, transport, keys, role):
        self.transport = transport
        self.records = RecordState(keys, role)
        self.send_queue = threading.RLock()

    @contextmanager
    def _queue(self):
        timeout = max(0.0, self.records.io_deadline() - time.monotonic())
        if not self.send_queue.acquire(timeout=timeout):
            self.abort()
            raise ProtocolError("send queue deadline")
        try:
            yield
        finally:
            self.send_queue.release()

    def _send(self, operation):
        with self._queue():
            try:
                raw = operation()
                self.transport.send(raw, self.records.io_deadline())
            except RecordLimit as limit:
                if not self.records.send_closed:
                    self.send_close(limit.reason)
                raise
            except BaseException:
                self.abort()
                raise

    def send_data(self, plaintext):
        self._send(lambda: self.records.encode_data(plaintext))

    def send_close(self, reason=0):
        self._send(lambda: self.records.encode_close(reason))

    def receive(self):
        try:
            raw = self.transport.recv(kinds=(DATA, CLOSE), role=1 - self.records.role,
                                      sid=self.records.sid, sequence=self.records.receive_sequence,
                                      deadline=self.records.io_deadline())
            result = self.records.decode(raw)
            if result[0] == CLOSE and not self.records.send_closed:
                self.send_close()
            return result
        except RecordLimit as limit:
            if not self.records.send_closed:
                self.send_close(limit.reason)
            raise
        except BaseException:
            self.abort()
            raise

    def shutdown(self):
        # send_closed is set at encoding, so serialize shutdown with the final
        # complete socket write, including when peer CLOSE races local CLOSE.
        with self._queue():
            if not self.records.closed or self.records.failed:
                self.abort()
                raise ProtocolError("both authenticated CLOSE records required")
            try:
                self.transport.shutdown(self.records.io_deadline())
            finally:
                self.abort()

    def abort(self):
        self.records.abort()
        self.transport.close()
