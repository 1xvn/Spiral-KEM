"""Replay an ordered controller journal independently of the live processes."""
from cross_host_smoke import require
from wire_contract import WireTracker, IDENTIFIERS
from backpressure_contract import integer

HEALTHY = (1, 2, 3)
GAP_NS = 5_000_000_000


def validate(case, journal, exits, remote=None):
    require(case in ('hold', 'release', 'timeout'), 'unknown scenario')
    mode = 'timeout' if case == 'timeout' else 'release'
    expected_exits = {'gate': 0, **{str(i): int(i == 0 and mode == 'timeout') for i in range(5)}}
    require(exits == expected_exits and all(type(code) is int for code in exits.values()), 'process exit or watchdog failure')
    times = [row['ns'] for row in journal]
    require(all(integer(t, 0, 2**63-1) for t in times) and times == sorted(times), 'invalid clock order')
    require(times and times[-1]-times[0] <= 120_000_000_000, 'overall budget exceeded')
    events = []
    tracker = WireTracker(mode)
    for index, row in enumerate(journal):
        origin, value = row['origin'], row['data']
        if origin == 'gate' and value.get('event') == 'server_endpoint':
            origin, value = 'server', value['payload']
        require(origin in ('control','gate','server','0','1','2','3','4') and isinstance(value,dict),
                'unknown event origin or shape')
        events.append((index, origin, value))

    def matches(origin, kind, lane=None):
        return [(i, v) for i, src, v in events if src == origin and v.get('event') == kind
                and (lane is None or v.get('lane') == lane)]

    def only(origin, kind, lane=None):
        found = matches(origin, kind, lane)
        require(len(found) == 1, f'missing or duplicate {origin}/{kind}/{lane}')
        return found[0]

    def identity(value):
        result = []
        for key, size in IDENTIFIERS:
            v = value[key]
            require(isinstance(v, str) and len(v) == size and any(c != '0' for c in v)
                    and all(c in '0123456789abcdef' for c in v), 'invalid identity')
            result.append(v)
        return tuple(result)

    def final(origin):
        results = [v for _, src, v in events if src == origin and 'status' in v]
        require(len(results) == 1, 'missing or duplicate final report')
        return results[0]

    ids = {lane: identity(only('server', 'lane_ready', lane)[1]) for lane in range(5)}
    require(all(len({i[k] for i in ids.values()}) == 5 for k in range(3)), 'reused peer identifier')
    pause = only('control', 'pause')[0]
    start = only('gate', 'gate_stall_confirmed')[0]
    fence = only('control', 'overlap_verified')[0]
    reclaimed, slot = only('server', 'reclaimed', 0)
    replacement = only('server', 'lane_ready', 4)[0]
    require(pause < start < fence < reclaimed < replacement, 'invalid phase order')
    require((slot['active'], slot['pending'], slot['live_keys']) == (3, 0, 0)
            and identity(slot) == ids[0], 'slot or native keys still held')
    for lane in range(4):
        kind = 'wire_ready' if lane == 0 else 'lane_ready'
        i, peer = only(str(lane), kind)
        require(i < pause and only('server','lane_ready',lane)[0] < pause and identity(peer) == ids[lane],
                'four peers not bound before pause')
    require(identity(only('4','lane_ready')[1]) == ids[4], 'replacement binding differs')
    # Use the single-session implementation's validators for the exact same
    # TCP/flow/gate events. The mixed server has a different final envelope.
    for _, src, v in events:
        kind = v.get('event')
        if src == 'control' and kind in ('pause','resume'):
            command = tracker.pause_command() if kind == 'pause' else tracker.resume_command()
            require(command == v['command'], 'gate command targets another peer')
        elif src == 'gate' and kind not in ('gate_finished','source_verified'):
            tracker.observe_remote(v)
        elif src == 'server' and (kind in tracker.expected['server'] or 'listening' in v):
            tracker.observe_remote({'event':'server_endpoint','payload':v})
        elif src == '0' and kind is not None:
            tracker.observe_client(v)
        elif src == 'server':
            require(kind in ('lane_ready','echoed','reclaimed') or 'status' in v,
                    'unexpected server event')
        elif src in ('1','2','3','4'):
            require((kind in ('verified','lane_ready') and v.get('lane')==int(src)) or 'status' in v,
                    'unexpected healthy endpoint event')
    require(tracker.identifiers and identity(tracker.identifiers) == ids[0], 'bad target binding')
    for role in ('client','server'):
        required = [k for k in tracker.expected[role] if k != 'failure_cleanup']
        require([v['event'] for v in tracker.events[role]] == required, 'missing target diagnostics')
    pid = only('gate','owned_server_started')[1]['child_pid']
    stop, end = only('gate','gate_finished')
    require(end['case'] == mode and end['child_pid'] == pid and end['child_exit_code'] == 0
            and end['reaped'] is True and end['listener_present'] is False
            and end['reads_held_until_server_exit'] is (mode=='timeout'), 'gate teardown differs')
    terminal = only('server','wire_timeout')[0] if mode == 'timeout' else only('gate','gate_resumed')[0]
    require(fence < terminal < reclaimed < stop, 'wrong terminal cause or resume order')
    if mode == 'timeout':
        require(not matches('control','resume') and not matches('gate','gate_resumed'), 'unexpected resume')
    if case == 'hold':
        require(times[fence]-times[start] >= 5_000_000_000, 'sustained hold too short')

    if remote is not None:
        receipt_index, receipt = only('gate','source_verified')
        require(receipt_index > stop and receipt['git_head']==remote['source']['git_head']
                and receipt['source_tree_sha256']==remote['source']['source_tree_sha256']
                and receipt['binary_sha256']==remote['binary_sha256'], 'remote provenance mismatch')
    require(len(matches('server','lane_ready')) == 5, 'unexpected authenticated lane')
    expected_controls = {'pause','resume','overlap_verified','echo','close','replacement_closed'}
    require(all(v.get('event') in expected_controls for _,src,v in events if src=='control'),
            'unexpected controller event')
    last_ack = []
    next_sample = []
    counts = {}
    worst = {}
    release_bytes = tracker.stalled['wire_snapshot']['bytes_written']
    for lane in (*HEALTHY, 4):
        verified = matches(str(lane), 'verified')
        echoed = matches('server', 'echoed', lane)
        commands = matches('control', 'echo', lane)
        require(0 < len(verified) == len(echoed) == len(commands) <= 512, 'missing echo evidence')
        for seq, ((i, ack), (j, sent), (q, cmd)) in enumerate(zip(verified, echoed, commands)):
            require(identity(ack) == identity(sent) == ids[lane] and ack['lane'] == lane
                    and all(type(x['sequence']) is int and x['sequence'] == seq for x in (ack,sent,cmd))
                    and q < min(i,j), 'payload sequence or binding mismatch')
            if start < q and max(i,j) < terminal:
                require(sent['stalled_bytes'] == release_bytes and sent['stalled_pending'] is True
                        and sent['stalled_state'] == 0 and (sent['active'],sent['pending']) == (4,0),
                        'sibling advanced or left OPEN during measured overlap')
        if lane in HEALTHY:
            during = [(q, max(i,j)) for (q,_),(i,_),(j,_) in zip(commands,verified,echoed)
                      if start < q and max(i,j) < fence]
            require(len(during) >= 11 and during[-1][0] > during[-2][1],
                    'missing post-acknowledgment TCP witness')
            require(max(verified[0][0],echoed[0][0]) < pause and
                    (echoed[0][1]['active'],echoed[0][1]['pending'])==(4,0),
                    'baseline without four established peers')
            before_end = [i for i,v in echoed if start < i < terminal and v['stalled_pending'] is True
                          and v['stalled_state']==0 and v['stalled_bytes']==release_bytes]
            require(before_end and times[terminal]-times[before_end[-1]] <= GAP_NS,
                    'missing recent healthy progress at release or deadline')
            last_ack.append(during[-2][1])
            next_sample.append(during[-1][0])
            require(commands[0][0] < pause and commands[-1][0] > replacement,
                    'healthy peer did not span replacement')
        else:
            require(commands[0][0] > replacement and any(v['active']==4 and v['pending']==0 for _,v in echoed),
                    'replacement did not occupy fourth slot')
        close_cmd = only('control','close',lane)[0]
        require(close_cmd > verified[-1][0] and (lane==4 or close_cmd > only('control','replacement_closed')[0]),
                'healthy session closed before recovery')
        points = [times[only(str(lane),'lane_ready')[0]], *(times[i] for i,_ in verified), times[close_cmd]]
        worst[lane] = max(b-a for a,b in zip(points,points[1:]))
        require(worst[lane] <= GAP_NS, 'healthy progress deadline missed')
        counts[lane] = len(verified)
    require(min(next_sample) > max(last_ack), 'overlap fence preceded a sibling acknowledgment')
    sf = final('server')
    require(sf['status']=='passed' and sf['connections']==5 and sf['admission_released'] is True
            and sf['auth_key_closed'] is True and len(sf['sessions'])==5, 'incomplete server shutdown')
    for lane in range(5):
        peer = final(str(lane))
        require(peer['kem']=={'executed_jobs':1,'live_keys':0,'rejected_jobs':0}, 'client worker leak')
        if lane == 0:
            require(peer['status']==('failed' if mode=='timeout' else 'passed'), 'wrong stalled client result')
            if mode=='release':
                require(peer['sessions'][0]['authenticated_close'] is True, 'bad release close')
            continue
        require(peer['status']=='passed' and peer['connections']==1 and len(peer['sessions'])==1, 'bad peer exit')
        reports = [v for v in sf['sessions'] if v.get('lane')==lane] + peer['sessions']
        require(len(reports)==2 and all(identity(v)==ids[lane] and v['verified']==counts[lane]
                and v['authenticated_close'] is True for v in reports), 'session close mismatch')
    require([v for v in sf['sessions'] if v.get('lane')==0] == [slot], 'server lost target receipt')
    require(sf['kem']=={'executed_jobs':10,'live_keys':0,'rejected_jobs':0}, 'shared pool did not drain')
    return {'status':'passed','case':case,'server_pid':pid,'verified_echoes':counts,
            'max_observed_progress_gap_ms':{k:v/1e6 for k,v in worst.items()},
            'stable_wire_bytes':release_bytes,'reclaimed':slot,'exits':exits}
