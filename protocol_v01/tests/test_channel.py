"""Channel queue and failure tests with event-controlled local transports."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from protocol_v01.channel import Channel
from protocol_v01 import records
from protocol_v01.records import RecordState, CLOSE
from protocol_v01.wire import ProtocolError, parse_frame


class WatchingRLock:
    """Expose when a named worker actually attempts to acquire the queue."""
    def __init__(self, watched_name):
        self.lock = threading.RLock()
        self.watched_name = watched_name
        self.attempted = threading.Event()

    def acquire(self, *, timeout):
        if threading.current_thread().name == self.watched_name:
            self.attempted.set()
        return self.lock.acquire(timeout=timeout)

    def release(self):
        self.lock.release()


class EventTransport:
    def __init__(self, *, block_kind=None, fail_send=False):
        self.block_kind = block_kind
        self.fail_send = fail_send
        self.closed = False
        self.incoming = []
        self.attempts = []
        self.completed = []
        self.order = []
        self.send_entered = threading.Event()
        self.release_send = threading.Event()
        self.shutdown_entered = threading.Event()
        self.closed_event = threading.Event()

    def send(self, raw, deadline):
        frame = parse_frame(raw)
        self.attempts.append(raw)
        if self.fail_send:
            raise ProtocolError('simulated partial send failure')
        if self.block_kind == frame.header.kind and len(self.attempts) == 1:
            self.send_entered.set()
            if not self.release_send.wait(1.5):
                raise ProtocolError('test transport release timeout')
        if self.closed or time.monotonic() >= deadline:
            raise ProtocolError('closed or deadline')
        self.completed.append(raw)
        self.order.append(('send', frame.header.kind))

    def recv(self, *, kinds, role, sid, sequence, deadline):
        if self.closed:
            raise ProtocolError('closed')
        raw = self.incoming.pop(0)
        frame = parse_frame(raw, role=role, sid=sid, sequence=sequence)
        if frame.header.kind not in kinds:
            raise ProtocolError('unexpected kind')
        return raw

    def shutdown(self, deadline):
        if self.closed or time.monotonic() >= deadline:
            raise ProtocolError('closed or deadline')
        self.shutdown_entered.set()
        self.order.append(('shutdown', None))

    def close(self):
        self.closed = True
        self.closed_event.set()
        # Closing a real socket interrupts a blocked write. Model that here.
        self.release_send.set()


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.keys = SimpleNamespace(sid=b'S'*16, c_key=b'C'*32, s_key=b'D'*32,
                                    c_prefix=b'CPFX', s_prefix=b'SPFX',
                                    transcript_hash=b'T'*32)

    def worker(self, operation, *, name, outcomes):
        def execute():
            try:
                operation()
            except BaseException as error:
                outcomes.append(error)
        thread = threading.Thread(target=execute, name=name, daemon=True)
        thread.start()
        return thread

    def test_peer_close_aborts_blocked_writer_at_close_queue_deadline(self):
        transport = EventTransport(block_kind=records.DATA)
        channel = Channel(transport, self.keys, 0)
        peer = RecordState(self.keys, 1)
        transport.incoming = [peer.encode_close()]
        failures = []
        writer = self.worker(lambda: channel.send_data(b'blocked data'),
                             name='blocked-writer', outcomes=failures)
        try:
            self.assertTrue(transport.send_entered.wait(1))
            with patch.object(records, 'CLOSE_GRACE', 0.05):
                started = time.monotonic()
                with self.assertRaises(ProtocolError):
                    channel.receive()
                elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.5, 'CLOSE grace waited behind old write deadline')
            self.assertTrue(transport.closed_event.is_set())
        finally:
            transport.release_send.set()
            writer.join(1)
        self.assertFalse(writer.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ProtocolError)
        self.assertTrue(channel.records.failed)
        self.assertTrue(transport.closed)
        self.assertIsNone(channel.records._send_key)
        self.assertIsNone(channel.records._receive_key)
        self.assertEqual(channel.records.send_sequence, 1)
        self.assertEqual(len(transport.attempts), 1)
        self.assertEqual(transport.completed, [])

    def test_tls_shutdown_waits_for_complete_final_close_write(self):
        transport = EventTransport(block_kind=CLOSE)
        channel = Channel(transport, self.keys, 0)
        queue = WatchingRLock('tls-shutdown')
        channel.send_queue = queue
        peer = RecordState(self.keys, 1)
        transport.incoming = [peer.encode_close()]
        failures = []
        writer = self.worker(channel.send_close, name='close-writer', outcomes=failures)
        shutdown = None
        try:
            self.assertTrue(transport.send_entered.wait(1))
            self.assertEqual(channel.receive(), (CLOSE, b'\0'))
            self.assertTrue(channel.records.closed)
            self.assertEqual(transport.completed, [])
            shutdown = self.worker(channel.shutdown, name='tls-shutdown', outcomes=failures)
            self.assertTrue(queue.attempted.wait(1))
            self.assertFalse(transport.shutdown_entered.wait(0.02),
                             'TLS shutdown overtook the encoded but unwritten CLOSE')
            transport.release_send.set()
            writer.join(1)
            shutdown.join(1)
        finally:
            transport.release_send.set()
            writer.join(1)
            if shutdown is not None:
                shutdown.join(1)
        self.assertFalse(writer.is_alive())
        self.assertFalse(shutdown.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(transport.order, [('send', CLOSE), ('shutdown', None)])
        self.assertTrue(transport.closed)

    def test_failed_send_aborts_and_cannot_retry_reserved_nonce(self):
        transport = EventTransport(fail_send=True)
        channel = Channel(transport, self.keys, 0)
        with self.assertRaises(ProtocolError):
            channel.send_data(b'first attempt')
        self.assertEqual(channel.records.send_sequence, 1)
        self.assertTrue(channel.records.failed)
        self.assertTrue(transport.closed)
        self.assertIsNone(channel.records._send_key)
        self.assertIsNone(channel.records._receive_key)
        with self.assertRaises(ProtocolError):
            channel.send_data(b'retry forbidden')
        self.assertEqual(channel.records.send_sequence, 1)
        self.assertEqual(len(transport.attempts), 1)
        self.assertEqual(parse_frame(transport.attempts[0]).header.sequence, 0)

    def test_concurrent_send_queue_preserves_encode_and_wire_order(self):
        transport = EventTransport(block_kind=records.DATA)
        channel = Channel(transport, self.keys, 0)
        queue = WatchingRLock('second-writer')
        channel.send_queue = queue
        failures = []
        first = self.worker(lambda: channel.send_data(b'first'), name='first-writer', outcomes=failures)
        second = None
        try:
            self.assertTrue(transport.send_entered.wait(1))
            second = self.worker(lambda: channel.send_data(b'second'), name='second-writer', outcomes=failures)
            self.assertTrue(queue.attempted.wait(1))
            # The second caller is at the outer queue, so it cannot reserve its
            # nonce or enter transport.send until the first write has finished.
            self.assertEqual(channel.records.send_sequence, 1)
            self.assertEqual(len(transport.attempts), 1)
            self.assertEqual(transport.completed, [])
            transport.release_send.set()
            first.join(1)
            second.join(1)
        finally:
            transport.release_send.set()
            first.join(1)
            if second is not None:
                second.join(1)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual([parse_frame(raw).header.sequence for raw in transport.completed], [0, 1])
        peer = RecordState(self.keys, 1)
        self.assertEqual([peer.decode(raw)[1] for raw in transport.completed], [b'first', b'second'])
        self.assertEqual(channel.records.send_sequence, 2)
        channel.abort()


if __name__ == '__main__':
    unittest.main()
