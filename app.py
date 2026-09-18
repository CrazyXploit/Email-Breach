from flask import Flask, request, jsonify
import requests, re, json

app = Flask(__name__)

DEVELOPER = "@techno_telex"
UPSTREAM = "https://databreach.com/_telefunc?_telefunc=txt"
IMG_BASE = "https://databreach-prod-public-images.s3.us-east-1.amazonaws.com/breaches"
BREACH_BASE = "https://databreach.com/breach"
UA = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36")


def detect_type(v):
    v = v.strip()
    if "@" in v:
        return "email"
    if 7 <= len(re.sub(r"\D", "", v)) <= 15:
        return "phone"
    return "email"


def telefunc(session, payload):
    r = session.post(
        UPSTREAM,
        data=json.dumps(payload),
        headers={
            "Content-Type": "text/plain",
            "x-telefunc-request": "txt",
            "Accept": "*/*",
            "Origin": "https://databreach.com",
            "Referer": "https://databreach.com/",
        },
        timeout=30,
    )
    return r.text


def shape_breach(b):
    bid = b.get("breach_id", "")
    return {
        "attack_date": b.get("attack_date"),
        "breach_id": bid,
        "breach_number": b.get("breach_number"),
        "field_counts": b.get("field_counts", {}),
        "found": b.get("found", []),
        "image": f"{IMG_BASE}/{bid}.webp",
        "label": b.get("label"),
        "link": f"{BREACH_BASE}/{bid}",
        "parsed_rows": b.get("parsed_rows"),
        "sensitive": b.get("sensitive"),
        "status": b.get("status"),
        "unverified": b.get("unverified"),
        "upload_date": b.get("upload_date"),
    }


def do_search(value):
    ptype = detect_type(value)
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept-Language": "en-IN,en;q=0.6"})
    try:
        s.get("https://databreach.com/", timeout=20)
    except Exception:
        pass

    body = telefunc(s, {
        "file": "/app/rpc/search.telefunc.ts",
        "name": "public_search",
        "args": [{
            "piis": [{"type": ptype, "value": value, "pii_id": "1"}],
            "main_breach_id": "!undefined",
        }],
    })

    try:
        parsed = json.loads(body)
    except Exception:
        return {
            "developer": DEVELOPER,
            "error": "bad upstream json",
            "raw": body[:400],
        }

    ret = parsed.get("ret", {}) or {}
    results = ret.get("results", []) or []
    breaches = [shape_breach(b) for b in results]

    return {
        "developer": DEVELOPER,
        "breaches": breaches,
        "hidden": ret.get("hiddenBreaches", 0),
        "query": value,
        "raw": parsed,
        "total": ret.get("totalBreaches", 0),
        "type": ptype,
        "visible": len(breaches),
    }


@app.route("/")
def home():
    return jsonify({
        "developer": DEVELOPER,
        "status": "ok",
        "usage": "/search?mail=test@example.com",
    })


@app.route("/search")
def search_route():
    value = (request.args.get("mail")
             or request.args.get("email")
             or request.args.get("q") or "").strip()
    if not value:
        return jsonify({
            "developer": DEVELOPER,
            "error": "missing ?mail=",
        }), 400
    return jsonify(do_search(value))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)