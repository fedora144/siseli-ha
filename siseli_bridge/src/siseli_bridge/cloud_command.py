import base64
import json
import os
import random
import string
import threading
import time

try:
    import paho.mqtt.client as mqtt
except Exception:
    mqtt = None


_started = False
_started_lock = threading.Lock()


def _log(msg):
    print(f"[MAX CHG CMD] {msg}", flush=True)


def _rand_token(n=8):
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(n))


def modbus_crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def build_max_total_charge_frame(amps: int) -> bytes:
    amps = int(round(float(amps)))
    if amps < 5:
        amps = 5
    if amps > 100:
        amps = 100

    # Solar of Thing confirmed:
    # Slave 05, Function 06, Register 0x139E, Value = amps
    frame = bytes([
        0x05,
        0x06,
        0x13,
        0x9E,
        (amps >> 8) & 0xFF,
        amps & 0xFF,
    ])
    crc = modbus_crc16(frame)
    return frame + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def build_max_total_charge_base64(amps: int) -> str:
    return base64.b64encode(build_max_total_charge_frame(amps)).decode("ascii")


def publish_cloud_command(amps: int):
    if mqtt is None:
        _log("paho-mqtt not available")
        return False

    amps = int(round(float(amps)))
    if amps < 5:
        amps = 5
    if amps > 100:
        amps = 100

    dtu_id = os.getenv("SISIELI_DTU_ID") or os.getenv("SISELI_DTU_ID") or os.getenv("DTU_ID") or "81520839086957145360"

    cloud_host = os.getenv("TARGET_HOST", "8.212.18.157")
    cloud_port = int(os.getenv("TARGET_PORT", "1883"))

    cloud_topic = os.getenv(
        "SISELI_CLOUD_COMMAND_TOPIC",
        f"dtu/{dtu_id}/sub/service/dev_rpc"
    )

    co = build_max_total_charge_base64(amps)

    payload = {
        "c": 5,
        "t": _rand_token(8),
        "s": _rand_token(9),
        "i": 504,
        "b": {
            "sa": "",
            "co": co,
            "no": 0
        }
    }

    payload_text = json.dumps(payload, separators=(",", ":"))

    client_id = f"ha_maxchg_{dtu_id}_{_rand_token(5)}"
    client = mqtt.Client(client_id=client_id, clean_session=True)

    try:
        _log(f"cloud connect {cloud_host}:{cloud_port}")
        client.connect(cloud_host, cloud_port, 10)
        client.loop_start()

        info = client.publish(cloud_topic, payload_text, qos=0, retain=False)
        info.wait_for_publish(timeout=5)

        _log(f"sent {amps}A co={co} topic={cloud_topic}")

        time.sleep(0.5)
        client.loop_stop()
        client.disconnect()
        return True

    except Exception as e:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass
        _log(f"cloud publish failed: {e}")
        return False


def start_max_total_charge_command_sidecar():
    global _started

    with _started_lock:
        if _started:
            return
        _started = True

    if mqtt is None:
        _log("disabled: paho-mqtt not available")
        return

    thread = threading.Thread(target=_sidecar_thread, name="max_total_charge_command_sidecar", daemon=True)
    thread.start()
    _log("sidecar started")


def _sidecar_thread():
    local_host = os.getenv("MQTT_HOST", "core-mosquitto")
    local_port = int(os.getenv("MQTT_PORT", "1883"))

    base_topic = os.getenv("STATE_TOPIC", "siseli/siseli_inverter_1/state").rsplit("/", 1)[0]
    command_topic = f"{base_topic}/command/max_total_charge_current/set"

    discovery_topic = "homeassistant/number/siseli_inverter_1/max_total_charge_current/config"

    state_topic = f"{base_topic}/command/max_total_charge_current/state"

    discovery_payload = {
        "name": "Siseli Max Total Charge Current",
        "uniq_id": "siseli_inverter_1_max_total_charge_current",
        "cmd_t": command_topic,
        "stat_t": state_topic,
        "min": 5,
        "max": 100,
        "step": 5,
        "mode": "box",
        "unit_of_meas": "A",
        "ic": "mdi:current-dc",
        "dev": {
            "ids": ["siseli_inverter_1"],
            "name": "Siseli Inverter 1",
            "mf": "Siseli Compatible",
            "mdl": "PS4Z"
        }
    }

    def on_connect(client, userdata, flags, rc):
        _log(f"local mqtt connected rc={rc}")
        client.publish(discovery_topic, json.dumps(discovery_payload), qos=0, retain=True)
        client.subscribe(command_topic)

        dtu_id = os.getenv("SISIELI_DTU_ID") or os.getenv("SISELI_DTU_ID") or os.getenv("DTU_ID") or "81520839086957145360"
        reply_topic = f"dtu/{dtu_id}/pub/service/dev_rpc_reply"
        client.subscribe(reply_topic)

        _log(f"subscribed {command_topic}")
        _log(f"subscribed {reply_topic}")

    def on_message(client, userdata, msg):
        try:
            topic = msg.topic
            raw = msg.payload.decode("utf-8", "ignore").lstrip("\x00").strip()

            # HA number command topic
            if topic == command_topic:
                amps = int(round(float(raw)))
                _log(f"HA command received: {amps}A")
                ok = publish_cloud_command(amps)

                echo_topic = f"{base_topic}/command/max_total_charge_current/result"
                client.publish(echo_topic, json.dumps({"amps": amps, "ok": ok}), qos=0, retain=False)
                if ok:
                    client.publish(state_topic, str(amps), qos=0, retain=True)
                return

            # Inverter RPC reply mirrored by bridge:
            # {"c":5,...,"e":0,"b":{"co":"BQYTngAU7Ss="}}
            if topic.endswith("/pub/service/dev_rpc_reply"):
                try:
                    obj = json.loads(raw)
                    co = (((obj or {}).get("b") or {}).get("co") or "")
                    if not co:
                        return

                    frame = base64.b64decode(co)
                    if len(frame) >= 8 and frame[0] == 0x05 and frame[1] == 0x06 and frame[2] == 0x13 and frame[3] == 0x9E:
                        amps = (frame[4] << 8) | frame[5]
                        client.publish(state_topic, str(amps), qos=0, retain=True)
                        _log(f"reply confirms Max Total Charge Current={amps}A co={co}")
                except Exception as e:
                    _log(f"reply parse ignored: {e}")
                return

        except Exception as e:
            _log(f"command error: {e}")

    while True:
        try:
            client = mqtt.Client(client_id=f"siseli_maxchg_sidecar_{_rand_token(5)}", clean_session=True)
            client.on_connect = on_connect
            client.on_message = on_message

            _log(f"local mqtt connect {local_host}:{local_port}")
            client.connect(local_host, local_port, 30)
            client.loop_forever()

        except Exception as e:
            _log(f"local mqtt loop failed: {e}; retry in 10s")
            time.sleep(10)
