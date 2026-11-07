# Rust record state fuzz grammar v1 (fixed public test data only)
Input cap 258 bytes. Missing first/second bytes are zero. scenario = byte0 % 7, sender role = byte1 & 1. Starting Tx and Rx counters are identical; Rx local role = 1 - sender role. Ignore bytes beyond 258 and any incomplete final 4-byte command. Commands are 4-byte tuples (opcode,a,b,c) following the two-byte header, at most 64. Opcode is modulo 6.
Fixed key = bytes(range(32)); prefix = a0 a1 a2 a3; SID = bytes(range(0x10,0x20)). Both roles deliberately share public synthetic material for this isolated half-pair, not production keys.
MAX_RECORDS=2**20, MAX_BYTES=2**30-1. Scenario initial (sequence,bytes): 0=(0,0), 1=(MAX_RECORDS-2,0), 2=(MAX_RECORDS-1,0), 3=(MAX_RECORDS,0), 4=(0,MAX_BYTES-1), 5=(0,MAX_BYTES), 6=(0,MAX_BYTES-16383). closed=false,key_live=true for each. Scenario3 is explicit synthetic exhaustion boundary, not a normal reachable open session.
Lengths table L=[0,1,2,31,16383,16384,16385]. Plaintext of selected length: byte i is (b + i*c) % 256.
Operations:
0=data: Tx.data(plaintext length L[a%7], pattern b,c). Append successful emitted frame to stored list.
1=close: Tx.close(a), b/c ignored. Append successful emitted frame.
2=deliver: Rx.decode(stored[a%len(stored)]), or empty bytes if none. b/c ignored.
3=mutate: same stored selection, then mutation b%8: 0 flip byte c%len by 1; 1 truncate to c%len; 2 append byte c; 3 flip role byte7 by1; 4 flip SID byte12 by1; 5 flip last tag byte by1; 6 flip sequence byte35 by1; 7 flip header kind byte6 by1. Empty base stays empty except append mutation2.
4=craft: independently seal a complete frame using ring AEAD. Kind = DATA if a&1==0 else CLOSE. Base seq = current model/actual Rx.sequence (they must match after every step). Sequence selection (a>>1)%4: 0 expected,1 expected+1,2 expected.saturating_sub(1),3 MAX_RECORDS-1. Header role=sender_role xor ((a>>3)&1). SID fixed unless a&16, then SID firstbyte xor1. CLOSE plaintext one byte c (including invalid reasons>2), DATA length L[b%7] and pattern byte i=(c+i)%256. Use independently encoded header even for syntax-invalid fields. Nonce fixedprefix + chosen seq as BE64. Flip last tag byte if a&32. b's high bits ignored for DATA and all b ignored for CLOSE.
5=raw: candidate = bytes([a,b,c]) repeated c%17 times (0..48 bytes), then Rx.decode.
The Rust live harness compares exact operation result, emitted wire or decoded plaintext bytes, and Tx/Rx snapshots to independent uninstrumented model after every operation. It does not model channel timers, cross-direction closure, socket writes, handshake or TLS.
JSON output schema:
{"accepted": bool(no operation errors), "scenario": integer, "role": integer, "initial":{"tx":STATE,"rx":STATE}, "steps":[{"op":"data|close|deliver|mutate|craft|raw","result":RESULT,"tx":STATE,"rx":STATE}]}
STATE={"sequence":integer,"bytes":integer,"closed":boolean,"key_live":boolean}
Error RESULT={"ok":false,"error":"Input|Closed|Authentication|Limit2"}; any other production error is a harness assertion failure.
Tx success RESULT={"ok":true,"length":integer full wire length,"sha256":hex SHA256(fullwire)}.
Rx success RESULT={"ok":true,"kind":16|17,"length":integer plaintext length,"sha256":hex SHA256(plaintext)}.
Error semantics follow actual low-level halves: invalid Tx DATA clears key but leaves closed=false; Tx reason>2 returns Input before closed check and leaves state untouched; Limit2 leaves state untouched; exhausted Tx.close clears key but leaves closed=false; every Rx error closes Rx and clears key, preserving sequence/bytes. Only successful DATA increments byte counters; successful record increments sequence; successful CLOSE closes the relevant half and removes key.
Independent Python oracle must use separate cryptography implementation/own stdlib ChaCha reference, not Python RecordState's combined endpoint lifecycle.
