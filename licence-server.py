# license_server.py
import os, json, hashlib, time
from flask import Flask, request, jsonify

app = Flask(__name__)

# Use a real DB in prod — this is a flat JSON file for simplicity
DB_PATH = "licenses.json"

def load_db():
    if not os.path.exists(DB_PATH):
        return {}
    with open(DB_PATH) as f:
        return json.load(f)

def save_db(db):
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)

def sign_token(key: str, machine: str, ts: int) -> str:
    secret = os.environ["LICENSE_SECRET"]  # set this env var on your server
    raw = f"{key}:{machine}:{ts}:{secret}"
    return hashlib.sha256(raw.encode()).hexdigest()

# ── Admin: issue a key ────────────────────────────────────────────────────────
@app.route("/admin/issue", methods=["POST"])
def issue():
    if request.headers.get("X-Admin-Key") != os.environ["ADMIN_KEY"]:
        return jsonify({"ok": False}), 403
    data = request.json
    key  = data["key"]          # you generate this, e.g. "PSQ-XXXX-XXXX-XXXX"
    seats = data.get("seats", 1)
    db = load_db()
    db[key] = {"seats": seats, "machines": [], "issued_to": data.get("name", "")}
    save_db(db)
    return jsonify({"ok": True, "key": key})

# ── Activate (first run on a new machine) ─────────────────────────────────────
@app.route("/activate", methods=["POST"])
def activate():
    data    = request.json
    key     = data.get("key", "").strip().upper()
    machine = data.get("machine", "")
    db      = load_db()

    if key not in db:
        return jsonify({"ok": False, "reason": "Invalid license key."})

    record = db[key]
    if machine in record["machines"]:
        # Already activated on this machine — just verify
        pass
    elif len(record["machines"]) >= record["seats"]:
        return jsonify({"ok": False, "reason": 
            f"License already used on {record['seats']} machine(s). "
            f"Contact support to transfer."})
    else:
        record["machines"].append(machine)
        save_db(db)

    ts    = int(time.time())
    token = sign_token(key, machine, ts)
    return jsonify({"ok": True, "token": token, "ts": ts})

# ── Verify (every run) ────────────────────────────────────────────────────────
@app.route("/verify", methods=["POST"])
def verify():
    data    = request.json
    key     = data.get("key", "").strip().upper()
    machine = data.get("machine", "")
    db      = load_db()

    if key not in db:
        return jsonify({"ok": False, "reason": "Invalid key."})
    if machine not in db[key]["machines"]:
        return jsonify({"ok": False, "reason": "Not activated on this machine."})

    ts    = int(time.time())
    token = sign_token(key, machine, ts)
    return jsonify({"ok": True, "token": token, "ts": ts})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)