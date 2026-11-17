"""Failure-verdict contracts; no processes, network traffic or TLS started."""
import copy
import unittest

from backpressure_contract import PressureTracker

IDS = {'session_id': '12' * 16, 'binding_hash': '34' * 32, 'transcript_hash': '56' * 32}


def flow(**changes):
    value = {'allocated_buffers': 18, 'free_buffers': 18, 'in_use_buffers': 0,
             'buffer_limit': 18, 'buffer_capacity_bytes': 16440, 'buffer_waiters': 0,
             'active_sends': 0, 'send_slot_waiters': 0, 'send_slots_capacity': 8,
             'send_slots_in_use': None, 'send_channel_closed': True,
             'receive_queue_length': None, 'receive_queue_capacity': 8,
             'receive_delivery_waiters': 0, 'reader_done': True, 'writer_done': True,
             'state': 3, 'close_reason': 0}
    value.update(changes)
    return value


def traces(case):
    def event(role, name, **fields):
        return dict(IDS, role=role, case=case, event=name, **fields)

    live = {'reader_done': False, 'writer_done': False, 'state': 0,
            'send_channel_closed': False, 'send_slots_in_use': 0, 'receive_queue_length': 0}
    pressure = flow(**dict(live, free_buffers=0, in_use_buffers=18, buffer_waiters=8,
                           active_sends=10, send_slot_waiters=2, send_slots_in_use=8))
    client = [
        event('client', 'receiver_queue_saturated', held_buffers=0, queued_messages=8,
              stable_ms=210., snapshot=flow(**dict(live, receive_queue_length=8,
                                                  receive_delivery_waiters=1))),
        event('client', 'pressure_saturated', held_buffers=18, producer_tasks=10,
              completed_sends=0, stable_ms=210., snapshot=pressure),
    ]
    server = [event('server', 'seed_sent', sent_messages=18, payload_bytes=1024)]
    if case == 'release':
        client.append(event('client', 'pressure_released', released_buffers=1, held_buffers=17,
                            completed_sends=10, verified_echoes=10,
                            snapshot=flow(**dict(live, free_buffers=1, in_use_buffers=17))))
    elif case == 'cancel':
        client.append(event('client', 'producer_cancelled', cancelled_sends=10, held_buffers=18,
                            completed_sends=0, snapshot=flow(**dict(live, free_buffers=0, in_use_buffers=18))))
    client.append(event('client', 'flow_cleanup', drained=True, snapshot=flow()))
    server.append(event('server', 'flow_cleanup', drained=True,
                        snapshot=flow(allocated_buffers=2, free_buffers=2,
                                      close_reason=1 if case == 'timeout' else 0)))
    if case == 'timeout':
        client.append(event('client', 'pressure_timeout', elapsed_ms=59600., deadline_errors=0,
                            closed_errors=10, completed_sends=0, snapshot=flow()))
        server.append({'event': 'failure_cleanup', 'role': 'server', 'active': 0, 'pending': 0,
                       'auth_key_closed': True, 'drained': True})
    for role, values, jobs in (('client', client, 1), ('server', server, 2)):
        final = {'status': 'failed' if case == 'timeout' else 'passed',
                 'kem': {'live_keys': 0, 'rejected_jobs': 0, 'executed_jobs': jobs}}
        if case != 'timeout':
            session = dict(IDS, messages=10, payload_bytes=1024, authenticated_close=True,
                           backpressure_case=case)
            if role == 'client':
                session['backpressure'] = {'completed_sends': 10, 'verified_echoes': 10,
                                           'seed_messages': 18, 'authenticated_close': True}
            final.update(role=role, connections=1, sessions=[session])
            if role == 'server':
                final.update(admission_released=True, auth_key_closed=True)
        values.append(final)
    return {'client': client, 'server': server}


def verdict(case, records=None, codes=None, errors=None):
    tracker = PressureTracker(case)
    for role, values in (records or traces(case)).items():
        for value in values:
            tracker.observe(role, value)
    expected = 1 if case == 'timeout' else 0
    tracker.validate(codes or {'client': expected, 'server': expected},
                     errors or ({'client': b'Error: Deadline\n', 'server': b'Error: Closed\n'}
                                if case == 'timeout' else {'client': b'', 'server': b''}))
    return tracker


class PressureContracts(unittest.TestCase):
    def test_accepts_all_three_bounded_scenarios(self):
        for case in ('release', 'cancel', 'timeout'):
            with self.subTest(case=case):
                tracker = verdict(case)
                self.assertEqual(tracker.identifiers, IDS)
                self.assertEqual(set(tracker.finals), {'client', 'server'})

    def test_independent_peers_may_arrive_in_either_order(self):
        for case in ('release', 'cancel', 'timeout'):
            values = traces(case)
            verdict(case, {'server': values['server'], 'client': values['client']})

    def test_rejects_unknown_case_and_unknown_endpoint_event(self):
        with self.assertRaises(ValueError):
            PressureTracker('flood')
        for role, value in (('other', {}), ('client', []), ('server', {'event': 'watchdog'})):
            with self.subTest(role=role), self.assertRaises(ValueError):
                PressureTracker('release').observe(role, value)

    def test_rejects_early_final_missing_or_reordered_phases(self):
        for index in range(4):
            values = traces('release')
            del values['client'][index]
            with self.subTest(missing=index), self.assertRaises(ValueError):
                verdict('release', values)
        values = traces('timeout')
        values['client'][2], values['client'][3] = values['client'][3], values['client'][2]
        with self.assertRaises(ValueError):
            verdict('timeout', values)

    def test_rejects_duplicate_phase_or_event_after_final(self):
        for index in (0, 4):
            values = traces('release')
            values['client'].insert(index, copy.deepcopy(values['client'][index]))
            with self.subTest(index=index), self.assertRaises(ValueError):
                verdict('release', values)

    def test_requires_matching_case_role_and_all_session_bindings(self):
        for name, changed in (('case', 'cancel'), ('role', 'client'), ('session_id', 'ab' * 16),
                              ('binding_hash', 'ab' * 32), ('transcript_hash', 'ab' * 32)):
            values = traces('release')
            values['server'][0][name] = changed
            with self.subTest(field=name), self.assertRaises(ValueError):
                verdict('release', values)

    def test_rejects_zero_nonhex_or_wrong_size_identifiers(self):
        for changed in ('0' * 32, 'z' * 32, '12'):
            values = traces('release')
            values['client'][0]['session_id'] = changed
            with self.subTest(value=changed), self.assertRaises(ValueError):
                verdict('release', values)

    def test_requires_actual_stable_receive_queue_pressure(self):
        for name, changed in (('held_buffers', 1), ('queued_messages', 7), ('stable_ms', 199.),
                              ('stable_ms', float('nan')), ('stable_ms', True)):
            values = traces('release')
            values['client'][0][name] = changed
            with self.subTest(field=name, value=changed), self.assertRaises(ValueError):
                verdict('release', values)
        for name, changed in (('receive_queue_length', 7), ('receive_delivery_waiters', 0)):
            values = traces('release')
            values['client'][0]['snapshot'][name] = changed
            with self.subTest(field=name), self.assertRaises(ValueError):
                verdict('release', values)
        for name in ('send_slots_in_use', 'receive_queue_length'):
            values = traces('release')
            del values['server'][1]['snapshot'][name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                verdict('release', values)

    def test_requires_exact_pool_and_send_reservation_pressure(self):
        for name, changed in (('buffer_waiters', 7), ('active_sends', 9),
                              ('send_slot_waiters', 1), ('send_slots_in_use', 7),
                              ('free_buffers', 1), ('in_use_buffers', 17)):
            values = traces('release')
            values['client'][1]['snapshot'][name] = changed
            with self.subTest(field=name), self.assertRaises(ValueError):
                verdict('release', values)
        values = traces('release')
        values['client'][1]['completed_sends'] = 1
        with self.assertRaises(ValueError):
            verdict('release', values)

    def test_rejects_changed_limits_overflow_or_invalid_snapshot_counters(self):
        for name, changed in (('buffer_limit', 19), ('buffer_capacity_bytes', 16441),
                              ('send_slots_capacity', 9), ('receive_queue_capacity', 9),
                              ('allocated_buffers', 19), ('receive_queue_length', 9),
                              ('active_sends', -1), ('buffer_waiters', True),
                              ('reader_done', 1), ('free_buffers', '18')):
            values = traces('release')
            values['client'][0]['snapshot'][name] = changed
            with self.subTest(field=name), self.assertRaises(ValueError):
                verdict('release', values)

    def test_requires_one_buffer_release_and_ten_verified_echoes(self):
        for name, changed in (('released_buffers', 2), ('held_buffers', 0),
                              ('completed_sends', 9), ('verified_echoes', 9)):
            values = traces('release')
            values['client'][2][name] = changed
            with self.subTest(field=name), self.assertRaises(ValueError):
                verdict('release', values)

    def test_requires_all_cancelled_producers_and_no_retained_reservations(self):
        for name, changed in (('cancelled_sends', 9), ('held_buffers', 0), ('completed_sends', 1)):
            values = traces('cancel')
            values['client'][2][name] = changed
            with self.subTest(field=name), self.assertRaises(ValueError):
                verdict('cancel', values)
        for name in ('active_sends', 'buffer_waiters', 'send_slot_waiters', 'send_slots_in_use'):
            values = traces('cancel')
            values['client'][2]['snapshot'][name] = 1
            with self.subTest(field=name), self.assertRaises(ValueError):
                verdict('cancel', values)

    def test_requires_both_readers_writers_and_every_buffer_drained(self):
        for role, index in (('client', 3), ('server', 1)):
            for name, changed in (('reader_done', False), ('writer_done', False),
                                  ('receive_delivery_waiters', 1), ('active_sends', 1),
                                  ('free_buffers', 0)):
                values = traces('release')
                values[role][index]['snapshot'][name] = changed
                with self.subTest(role=role, field=name), self.assertRaises(ValueError):
                    verdict('release', values)

    def test_timeout_accepts_peer_expiry_race_but_requires_positive_expiry(self):
        values = traces('timeout')
        verdict('timeout', values)
        values['server'][1]['snapshot']['close_reason'] = 0
        with self.assertRaises(ValueError):
            verdict('timeout', values)
        values['client'][3].update(deadline_errors=1, closed_errors=9)
        verdict('timeout', values)

    def test_timeout_requires_real_deadline_cohort_and_no_success(self):
        for name, changed in (('elapsed_ms', 54999.), ('elapsed_ms', float('inf')),
                              ('deadline_errors', -1), ('closed_errors', 9), ('completed_sends', 1)):
            values = traces('timeout')
            values['client'][3][name] = changed
            with self.subTest(field=name), self.assertRaises(ValueError):
                verdict('timeout', values)

    def test_timeout_rejects_watchdog_kill_authentication_and_missing_error(self):
        for code in (0, 124, 137, -15):
            with self.subTest(code=code), self.assertRaises(ValueError):
                verdict('timeout', codes={'server': code, 'client': 1})
        for text in (b'', b'Error: Transport\n', b'Error: Authentication\n',
                     b'Error: Closed\nError: Deadline\n'):
            with self.subTest(error=text), self.assertRaises(ValueError):
                verdict('timeout', errors={'client': b'Error: Deadline\n', 'server': text})

    def test_timeout_requires_server_admission_and_identity_cleanup(self):
        for name, changed in (('active', 1), ('pending', 1), ('auth_key_closed', False), ('drained', False)):
            values = traces('timeout')
            values['server'][2][name] = changed
            with self.subTest(field=name), self.assertRaises(ValueError):
                verdict('timeout', values)

    def test_requires_native_cleanup_handshake_accounting_and_success_echo_details(self):
        for case in ('release', 'timeout'):
            for name, changed in (('live_keys', 1), ('rejected_jobs', 1), ('executed_jobs', 0)):
                values = traces(case)
                values['client'][-1]['kem'][name] = changed
                with self.subTest(case=case, field=name), self.assertRaises(ValueError):
                    verdict(case, values)
        values = traces('cancel')
        values['client'][-1]['sessions'][0]['backpressure']['verified_echoes'] = 9
        with self.assertRaises(ValueError):
            verdict('cancel', values)

    def test_success_requires_final_case_and_session_binding(self):
        for name, changed in (('backpressure_case', 'timeout'), ('payload_bytes', 1),
                              ('session_id', 'ab' * 16)):
            values = traces('release')
            values['client'][-1]['sessions'][0][name] = changed
            with self.subTest(field=name), self.assertRaises(ValueError):
                verdict('release', values)


if __name__ == '__main__':
    unittest.main()
