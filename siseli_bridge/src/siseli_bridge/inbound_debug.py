
import os
import json
import base64
import threading
import time

_started = False

def _log(msg):
    print(f"[INBOUND DBG] {msg}", flush=True)

def _decode_remaining_length(data, pos=1):
    multiplier = 1
    value = 0
    while pos < len(data):
        encoded = data[pos]
        value += (encoded & 127) * multiplier
        pos += 1
        if (encoded & 128) == 0:
            return value, pos
        multiplier *= 128
        if multiplier > 128*128*128:
            break
    return None, pos

def _parse_publish(data):
    if not data or (data[0] >> 4) != 3:
        return None

    rem_len, pos = _decode_remaining_length(data, 1)
    if rem_len is None or pos + 2 > len(data):
        return None

    topic_len = (data[pos] << 8) | data[pos + 1]
    pos += 2
    if pos + topic_len > len(data):
        return None

    topic = data[pos:pos + topic_len].decode("utf-8", "ignore")
    pos += topic_len

    qos = (data[0] >> 1) & 0x03
    if qos:
        pos += 2

    payload = data[pos:]
    return topic, payload

def _parse_connect(data):
    if not data or (data[0] >> 4) != 1:
        return None

    try:
        rem_len, pos = _decode_remaining_length(data, 1)
        if rem_len is None:
            return None

        # Protocol name
        proto_len = (data[pos] << 8) | data[pos + 1]
        pos += 2 + proto_len

        # protocol level, flags, keepalive
        proto_level = data[pos]
        flags = data[pos + 1]
        keepalive = (data[pos + 2] << 8) | data[pos + 3]
        pos += 4

        def read_utf():
            nonlocal pos
            if pos + 2 > len(data):
                return ""
            l = (data[pos] << 8) | data[pos + 1]
            pos += 2
            s = data[pos:pos + l].decode("utf-8", "ignore")
            pos += l
            return s

        client_id = read_utf()

        username = ""
        password_len = 0

        # skip will topic/message if present
        will_flag = bool(flags & 0x04)
        if will_flag:
            _ = read_utf()
            _ = read_utf()

        if flags & 0x80:
            username = read_utf()

        if flags & 0x40:
            # don't print password
            if pos + 2 <= len(data):
                password_len = (data[pos] << 8) | data[pos + 1]

        return {
            "client_id": client_id,
            "username_present": bool(flags & 0x80),
            "username": username,
            "password_present": bool(flags & 0x40),
            "password_len": password_len,
            "keepalive": keepalive,
            "flags": flags,
        }
    except Exception:
        return None

def _safe_text(payload):
    if not payload:
        return ""

    # Solar payload often starts with 00 before JSON
    p = payload
    if p[:1] == b"\x00":
        p = p[1:]

    txt = p.decode("utf-8", "ignore")
    if len(txt) > 800:
        txt = txt[:800] + "...<truncated>"
    return txt

def _try_decode_co(payload):
    try:
        txt = _safe_text(payload).strip()
        if not txt.startswith("{"):
            return

        obj = json.loads(txt)
        co = (((obj or {}).get("b") or {}).get("co") or "")
        if not co:
            return

        frame = base64.b64decode(co)
        hexs = frame.hex(" ")
        if len(frame) >= 8:
            reg = (frame[2] << 8) | frame[3]
            val = (frame[4] << 8) | frame[5]
            _log(f"CO_DECODE co={co} frame={hexs} reg=0x{reg:04X} value={val}")
        else:
            _log(f"CO_DECODE co={co} frame={hexs}")
    except Exception as e:
        _log(f"CO_DECODE error={e}")

def _sniff_loop():
    try:
        from scapy.all import sniff, IP, TCP, Raw
    except Exception as e:
        _log(f"scapy import failed: {e}")
        return

    target = os.getenv("TARGET_HOST", "8.212.18.157")
    inv_ip = os.getenv("INVERTER_IP", "")

    _log(f"started target={target}:1883 inverter={inv_ip or 'auto'}")

    def handle(pkt):
        try:
            if IP not in pkt or TCP not in pkt or Raw not in pkt:
                return

            ip = pkt[IP]
            tcp = pkt[TCP]
            raw = bytes(pkt[Raw].load)

            if not raw:
                return

            # only cloud MQTT traffic
            if not (ip.src == target or ip.dst == target or tcp.sport == 1883 or tcp.dport == 1883):
                return

            direction = "unknown"
            if ip.src == target:
                direction = "cloud_to_inverter"
            elif ip.dst == target:
                direction = "inverter_to_cloud"

            first16 = raw[:16].hex()
            _log(f"RAW direction={direction} {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} len={len(raw)} first16={first16}")

            c = _parse_connect(raw)
            if c:
                user_show = c.get("username") or ""
                if len(user_show) > 6:
                    user_show = user_show[:3] + "***" + user_show[-2:]
                _log(
                    "CONNECT "
                    f"direction={direction} client_id={c.get('client_id')} "
                    f"username_present={c.get('username_present')} username={user_show} "
                    f"password_present={c.get('password_present')} password_len={c.get('password_len')} "
                    f"keepalive={c.get('keepalive')} flags=0x{c.get('flags'):02x}"
                )
                return

            pub = _parse_publish(raw)
            if pub:
                topic, payload = pub
                text = _safe_text(payload)
                _log(f"MQTT_PUBLISH direction={direction} topic={topic} payload_len={len(payload)} payload_text={text}")
                _try_decode_co(payload)
                return

        except Exception as e:
            _log(f"packet error: {e}")

    while True:
        try:
            sniff(filter="tcp port 1883", prn=handle, store=False, timeout=30)
        except Exception as e:
            _log(f"sniff error: {e}")
            time.sleep(5)

def start_inbound_debug():
    global _started
    if _started:
        return
    _started = True

    t = threading.Thread(target=_sniff_loop, daemon=True)
    t.start()
    _log("thread started")
