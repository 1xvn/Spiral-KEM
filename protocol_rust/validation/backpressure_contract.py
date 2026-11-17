"""Strict verdicts for the opt-in bounded slow-consumer probe; no I/O."""
import math

import cross_host_smoke as base

IDENTIFIERS = (('session_id', 32), ('binding_hash', 64), ('transcript_hash', 64))
CASES = ('release', 'cancel', 'timeout')


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def duration(value, minimum):
    return type(value) in (int, float) and math.isfinite(value) and value >= minimum


def snapshot(value):
    base.require(isinstance(value, dict), 'missing flow snapshot')
    base.require('send_slots_in_use' in value and 'receive_queue_length' in value,
                 'incomplete nullable flow counters')
    limits = {'buffer_limit': 18, 'buffer_capacity_bytes': 16440,
              'send_slots_capacity': 8, 'receive_queue_capacity': 8}
    for name, expected in limits.items():
        base.require(type(value.get(name)) is int and value[name] == expected,
                     'production flow limit differs: ' + name)
    for name, high in (('allocated_buffers', 18), ('free_buffers', 18),
                       ('in_use_buffers', 18), ('buffer_waiters', 10),
                       ('active_sends', 10), ('send_slot_waiters', 10),
                       ('receive_delivery_waiters', 1), ('state', 3), ('close_reason', 255)):
        base.require(integer(value.get(name), 0, high), 'invalid flow counter: ' + name)
    base.require(value['free_buffers'] + value['in_use_buffers'] == value['allocated_buffers'],
                 'buffer ownership accounting differs')
    for name in ('send_channel_closed', 'reader_done', 'writer_done'):
        base.require(type(value.get(name)) is bool, 'invalid flow flag: ' + name)
    slots = value.get('send_slots_in_use')
    base.require((slots is None and value['send_channel_closed']) or integer(slots, 0, 8),
                 'invalid send-slot accounting')
    queued = value.get('receive_queue_length')
    base.require(queued is None or integer(queued, 0, 8), 'receive queue exceeds bound')
    return value


def no_producers(value):
    return all(value[name] == 0 for name in ('active_sends', 'buffer_waiters', 'send_slot_waiters')) \
        and value['send_slots_in_use'] in (None, 0)


def cleaned(value):
    return no_producers(value) and value['reader_done'] and value['writer_done'] \
        and value['free_buffers'] == value['allocated_buffers'] and value['in_use_buffers'] == 0 \
        and value['receive_delivery_waiters'] == 0


class PressureTracker:
    """Validate each peer's order independently and bind every phase to one session."""
    def __init__(self, case):
        base.require(case in CASES, 'unsupported backpressure case')
        self.case = case
        self.events = {'client': [], 'server': []}
        self.finals = {}
        self.identifiers = None
        self.expected = {
            'server': ['seed_sent', 'flow_cleanup'],
            'client': ['receiver_queue_saturated', 'pressure_saturated'],
        }
        if case == 'timeout':
            self.expected['server'] += ['failure_cleanup']
            self.expected['client'] += ['flow_cleanup', 'pressure_timeout']
        else:
            self.expected['client'] += [
                'pressure_released' if case == 'release' else 'producer_cancelled', 'flow_cleanup']

    def bind(self, event):
        identifiers = {}
        for name, size in IDENTIFIERS:
            value = event.get(name)
            base.require(isinstance(value, str) and len(value) == size and value != '0' * size
                         and all(c in '0123456789abcdef' for c in value),
                         'invalid session identifier: ' + name)
            identifiers[name] = value
        if self.identifiers is None:
            self.identifiers = identifiers
        base.require(self.identifiers == identifiers, 'backpressure session binding differs')

    def observe(self, role, event):
        base.require(role in self.events and isinstance(event, dict), 'invalid endpoint event')
        base.require(role not in self.finals, 'event after endpoint final')
        expected = self.expected[role]
        index = len(self.events[role])
        if 'status' in event:
            base.require(index == len(expected), 'endpoint ended before all pressure phases')
            self.finals[role] = event
            return
        base.require(index < len(expected) and event.get('event') == expected[index],
                     'missing, duplicate or reordered backpressure phase')
        name = event['event']
        base.require(event.get('role') == role, 'endpoint role differs')
        if name == 'failure_cleanup':
            base.require(event.get('active') == 0 and event.get('pending') == 0
                         and event.get('auth_key_closed') is True and event.get('drained') is True,
                         'server admission or identity ownership not released')
        else:
            base.require(event.get('case') == self.case, 'endpoint case differs')
            self.bind(event)
            self.check_phase(name, event)
        self.events[role].append(event)

    def check_phase(self, name, event):
        if name == 'seed_sent':
            base.require(event.get('sent_messages') == 18 and event.get('payload_bytes') == 1024,
                         'authenticated seed count differs')
            return
        value = snapshot(event.get('snapshot'))
        if name == 'receiver_queue_saturated':
            base.require(event.get('held_buffers') == 0 and event.get('queued_messages') == 8
                         and duration(event.get('stable_ms'), 200)
                         and value['receive_queue_length'] == 8 and value['receive_delivery_waiters'] == 1,
                         'actual receive-queue saturation was not observed')
        elif name == 'pressure_saturated':
            base.require(event.get('held_buffers') == 18 and event.get('producer_tasks') == 10
                         and event.get('completed_sends') == 0 and duration(event.get('stable_ms'), 200)
                         and value['allocated_buffers'] == 18 and value['free_buffers'] == 0
                         and value['in_use_buffers'] == 18 and value['buffer_waiters'] == 8
                         and value['active_sends'] == 10 and value['send_slot_waiters'] == 2
                         and value['send_slots_in_use'] == 8 and not value['send_channel_closed'],
                         'bounded producer pressure was not observed')
        elif name == 'pressure_released':
            base.require(event.get('released_buffers') == 1 and event.get('held_buffers') == 17
                         and event.get('completed_sends') == 10 and event.get('verified_echoes') == 10
                         and no_producers(value), 'one-buffer release did not restore progress')
        elif name == 'producer_cancelled':
            base.require(event.get('cancelled_sends') == 10 and event.get('held_buffers') == 18
                         and event.get('completed_sends') == 0 and no_producers(value)
                         and value['in_use_buffers'] == 18 and value['free_buffers'] == 0,
                         'cancelled producers retained reservations or buffers')
        elif name == 'flow_cleanup':
            base.require(event.get('drained') is True and cleaned(value), 'flow ownership not drained')
            if event['role'] == 'client':
                base.require(value['allocated_buffers'] == 18 and value['free_buffers'] == 18,
                             'client seed buffers were not all returned')
        elif name == 'pressure_timeout':
            deadlines = event.get('deadline_errors')
            closed = event.get('closed_errors')
            base.require(duration(event.get('elapsed_ms'), 55000)
                         and integer(deadlines, 0, 10) and integer(closed, 0, 10)
                         and deadlines + closed == 10 and event.get('completed_sends') == 0
                         and cleaned(value), 'blocked producers did not expire and drain')

    def validate(self, codes, errors):
        base.require(set(self.finals) == {'client', 'server'}, 'missing endpoint final')
        for role in ('client', 'server'):
            report = self.finals[role]
            kem = report.get('kem', {})
            base.require(kem.get('live_keys') == 0 and kem.get('rejected_jobs') == 0
                         and kem.get('executed_jobs') == {'server': 2, 'client': 1}[role],
                         'native key ownership or authenticated handshake accounting differs')
            terminal = [line.strip() for line in errors[role].splitlines()
                        if line.strip().startswith(b'Error:')]
            if self.case == 'timeout':
                allowed = (b'Error: Deadline',) if role == 'client' else (b'Error: Deadline', b'Error: Closed')
                base.require(codes[role] == 1 and report.get('status') == 'failed'
                             and len(terminal) == 1 and terminal[0] in allowed,
                             'unexpected timeout endpoint status or error category')
            else:
                base.require(codes[role] == 0 and not terminal, 'unexpected successful-case endpoint exit')
        if self.case == 'timeout':
            timeout = self.events['client'][-1]
            cleanup = [event for values in self.events.values() for event in values
                       if event['event'] == 'flow_cleanup']
            base.require(timeout['deadline_errors'] > 0
                         or any(event['snapshot']['close_reason'] == 1 for event in cleanup),
                         'no peer demonstrates the production deadline expiring')
        else:
            base.validate_pair(self.finals['server'], self.finals['client'])
            for role in ('server', 'client'):
                session = self.finals[role]['sessions'][0]
                self.bind(session)
                base.require(session.get('backpressure_case') == self.case
                             and session.get('payload_bytes') == 1024, 'final pressure case differs')
            result = self.finals['client']['sessions'][0].get('backpressure', {})
            base.require(result.get('completed_sends') == 10 and result.get('verified_echoes') == 10
                         and result.get('seed_messages') == 18 and result.get('authenticated_close') is True,
                         'post-pressure echo verification is incomplete')
