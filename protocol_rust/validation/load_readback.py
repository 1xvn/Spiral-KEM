"""Replay the raw probe stages and the collector's independent /proc trace."""
import math


def require(ok, message):
    if not ok:
        raise ValueError(message)


def count(value):
    return type(value) is int and value >= 0


def elapsed(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def readback(result, probe, resources, stderr):
    from load_campaign import ResourceSummary, resource_violation, strict_json, validate_final

    require(result['status'] == 'passed' and result['source_unchanged'] is True and
            result['binary_unchanged'] is True, 'collector failed or inputs changed')
    duration = result['requested_duration_seconds']
    lanes = result['requested_connections']
    payload = result['payload_bytes']
    wall = result['collector_monotonic_elapsed_seconds']
    require(stderr == b'' and result['probe_exit_code'] == 0 and elapsed(wall) and wall >= duration,
            'missing completion or insufficient collector monotonic time')
    phase = 'start'
    limits = set()
    required = {'per_ip_four_then_fifth_rejected_and_refill_recovered',
                'pending_32_then_33rd_rejected_idle_tls_timeout_and_recovery'}
    global_cap = 'active_64_then_65th_rejected'
    epochs = 0
    messages = 0
    epoch_messages = 0
    traffic_start = 0
    traffic_span = 0
    last_progress = 0
    for line in probe:
        require(line.endswith(b'\n'), 'truncated probe stream')
        row = strict_json(line)
        event = row['event']
        if event == 'start' and phase == 'start':
            require([row['connections'], row['duration_seconds'], row['payload_bytes'], row['interval_ms']]
                    == [lanes, duration, payload, result['interval_ms']], 'wrong probe request')
            baseline = row['resource_baseline']
            phase = 'limits'
        elif event == 'limit_case':
            label = row['id']
            require(row['status'] == 'passed' and row['rejected'] == 1 and label not in limits and
                    ((phase == 'limits' and label in required) or
                     (phase == 'ready' and lanes == 64 and label == global_cap and row['active_peak'] == lanes)),
                    'missing, duplicate or misplaced admission witness')
            if label.startswith('per_ip'):
                require(row['authenticated_pairs'] == 5, 'missing per-IP recovery')
            if label.startswith('pending'):
                require(row['pending_peak'] == 32, 'missing pending limit')
            limits.add(label)
        elif event == 'rotation_started' and phase in ('limits', 'closed_epoch'):
            require(required <= limits and row['completed_epochs'] == epochs and
                    row['initial'] is (epochs == 0), 'wrong rotation start')
            phase = 'rotation'
        elif event == 'rotation_progress' and phase == 'rotation':
            continue
        elif event == 'rotation_ready' and phase == 'rotation':
            require(row['active'] == row['expected_established_connections'] == lanes and row['pending'] == 0
                    and row['completed_epochs'] == epochs and row['initial'] is (epochs == 0)
                    and row['authenticated_pairs_total'] == 6 + lanes * (epochs + 1), 'incomplete rotation')
            phase = 'ready' if epochs == 0 else 'traffic_ready'
        elif event == 'soak_started' and phase == 'ready':
            require(row['duration_seconds'] == duration and row['active'] == lanes and
                    (lanes != 64 or global_cap in limits), 'incomplete soak start')
            phase = 'traffic_ready'
        elif event == 'traffic_started' and phase == 'traffic_ready':
            require(row['completed_epochs'] == epochs and row['expected_established_connections'] == lanes,
                    'wrong traffic epoch')
            traffic_start = last_progress = row['soak_elapsed_seconds']
            epoch_messages = messages
            phase = 'traffic'
        elif event == 'sample' and phase in ('traffic', 'closed_epoch'):
            live = phase == 'traffic'
            n = row['total_messages']
            at = row['soak_elapsed_seconds']
            require(count(n) and n >= messages and elapsed(at) and at >= last_progress and
                    row['completed_epochs'] == epochs and
                    row['expected_established_connections'] == (lanes if live else 0),
                    'invalid traffic counters')
            require(count(row['active']) and row['active'] <= lanes and row['pending'] == 0
                    and row['authenticated_pairs_total'] == 6 + lanes * (epochs + int(live))
                    and count(row['echoed_bytes']) and count(row['admission_rejected'])
                    and row['admission_rejected'] == len(limits) and
                    all(count(row['kem'][k]) for k in ('live_keys', 'rejected_jobs', 'executed_jobs')) and
                    row['kem']['rejected_jobs'] == 0 and
                    row['kem']['executed_jobs'] == 3 * row['authenticated_pairs_total'],
                    'incomplete traffic sample accounting')
            if live:
                require(at - last_progress <= 16, 'missing traffic progress')
            if n > messages:
                last_progress = at
            messages = n
            if not live:
                require(row['active'] == row['pending'] == row['kem']['live_keys'] == 0 and
                        row['echoed_bytes'] == n * payload, 'missing shutdown sample')
                shutdown = row
                phase = 'shutdown'
        elif event == 'closing_started' and phase == 'traffic':
            span = row['soak_elapsed_seconds'] - traffic_start
            require(elapsed(span) and span <= 242 and row['completed_epochs'] == epochs and
                    row['soak_elapsed_seconds'] - last_progress <= 16 and
                    (span < 2 or messages > epoch_messages), 'epoch lacks observed traffic')
            traffic_span += span
            epochs += 1
            phase = 'closed_epoch'
        elif event == 'final' and phase == 'shutdown':
            validate_final(row, duration, lanes)
            pairs = 6 + lanes * epochs
            require(row == result['probe_final'] and row['resource_baseline'] == baseline and
                    row['completed_epochs'] == epochs and row['requested_duration_seconds'] == duration and
                    row['authenticated_pairs_total'] == shutdown['authenticated_pairs_total'] == pairs and
                    row['total_messages'] == messages and row['echoed_bytes'] == messages * payload and
                    row['bidirectional_payload_bytes'] == 2 * messages * payload and
                    row['kem'] == shutdown['kem'] and row['kem']['rejected_jobs'] == 0 and
                    row['admission_rejected'] == shutdown['admission_rejected'] == len(limits) and
                    duration <= traffic_span <= wall + 0.1 and
                    row['traffic_epoch_elapsed_seconds'] <= traffic_span + 0.1 and
                    row['actual_elapsed_seconds'] <= wall + 0.1, 'inconsistent terminal accounting')
            phase = 'finished'
        else:
            raise ValueError('unexpected or missing probe phase: ' + event)
    require(phase == 'finished', 'incomplete probe transcript')

    summary = ResourceSummary()
    previous = None
    for line in resources:
        require(line.endswith(b'\n'), 'truncated resource stream')
        row = strict_json(line)
        at = row['elapsed_seconds']
        require(elapsed(at) and at <= wall and
                all(count(row[k]) for k in ('rss_kib', 'peak_rss_kib', 'fd_count', 'threads',
                                            'minor_faults', 'major_faults')) and elapsed(row['cpu_seconds'])
                and row['peak_rss_kib'] >= row['rss_kib']
                and not resource_violation(row, result['resource_limits']), 'invalid resource sample')
        if previous is not None:
            require(0 < at - previous['elapsed_seconds'] <= 4 and
                    all(row[k] >= previous[k] for k in ('cpu_seconds', 'major_faults', 'minor_faults')),
                    'resource trace discontinuity')
        else:
            first = at
        previous = row
        summary.add(row)
    require(summary.count >= 2 and summary.count == result['resource_samples'] and
            wall - previous['elapsed_seconds'] <= 4 and previous['elapsed_seconds'] - first >= duration - 2
            and summary.report() == result['resources'], 'resource trace does not cover campaign')
