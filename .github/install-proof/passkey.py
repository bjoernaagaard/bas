"""A software passkey for the install proof.

It enrolls with the broker's approval pages and approves one request, as a browser with a
security key does. It talks to the pages on their loopback address and sends the approval
origin in the Origin header. It uses the Python standard library and the openssl program.

    passkey.py enroll  https://ORIGIN/enroll/TOKEN
    passkey.py approve https://ORIGIN/a/ID
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

PAGES = "http://127.0.0.1:793"
KEY = "passkey.pem"
STATE = "passkey.json"
USER_PRESENT_AND_VERIFIED = 0x05
WITH_CREDENTIAL = 0x40


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def cbor(value) -> bytes:
    def head(major: int, number: int) -> bytes:
        if number < 24:
            return bytes([major << 5 | number])
        if number < 256:
            return bytes([major << 5 | 24, number])
        return bytes([major << 5 | 25]) + number.to_bytes(2, "big")

    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        return head(3, len(value)) + value.encode()
    return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())


def post(origin: str, path: str, body: dict) -> dict:
    request = urllib.request.Request(
        PAGES + path,
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", "origin": origin},
    )
    with urllib.request.urlopen(request) as reply:
        return json.load(reply)


def client_data(kind: str, challenge: str, origin: str) -> bytes:
    return json.dumps(
        {"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}
    ).encode()


def enroll(origin: str, path: str) -> None:
    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", KEY],
        check=True,
    )
    os.chmod(KEY, 0o600)
    public = subprocess.run(
        ["openssl", "ec", "-in", KEY, "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout[-64:]
    options = post(origin, path + "/begin", {"label": "install proof"})["publicKey"]
    credential = os.urandom(32)
    cose_key = cbor({1: 2, 3: -7, -1: 1, -2: public[:32], -3: public[32:]})
    authenticator_data = (
        hashlib.sha256(options["rp"]["id"].encode()).digest()
        + bytes([USER_PRESENT_AND_VERIFIED | WITH_CREDENTIAL])
        + bytes(4)
        + bytes(16)
        + len(credential).to_bytes(2, "big")
        + credential
        + cose_key
    )
    attestation = cbor({"fmt": "none", "attStmt": {}, "authData": authenticator_data})
    reply = post(
        origin,
        path + "/finish",
        {
            "label": "install proof",
            "credential": {
                "id": b64(credential),
                "rawId": b64(credential),
                "type": "public-key",
                "extensions": {},
                "response": {
                    "attestationObject": b64(attestation),
                    "clientDataJSON": b64(
                        client_data("webauthn.create", options["challenge"], origin)
                    ),
                },
            },
        },
    )
    with open(STATE, "w") as state:
        json.dump({"credential": b64(credential), "rp": options["rp"]["id"]}, state)
    print("enroll:", reply["state"])


def approve(origin: str, path: str) -> None:
    with open(STATE) as state:
        saved = json.load(state)
    options = post(origin, path + "/begin", {})["publicKey"]
    authenticator_data = (
        hashlib.sha256(saved["rp"].encode()).digest()
        + bytes([USER_PRESENT_AND_VERIFIED])
        + bytes(4)
    )
    data = client_data("webauthn.get", options["challenge"], origin)
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", KEY],
        input=authenticator_data + hashlib.sha256(data).digest(),
        check=True,
        capture_output=True,
    ).stdout
    reply = post(
        origin,
        path + "/finish",
        {
            "credential": {
                "id": saved["credential"],
                "rawId": saved["credential"],
                "type": "public-key",
                "extensions": {},
                "response": {
                    "authenticatorData": b64(authenticator_data),
                    "clientDataJSON": b64(data),
                    "signature": b64(signature),
                    "userHandle": None,
                },
            }
        },
    )
    print("approve:", reply["state"])
    if reply["state"] != "approved":
        sys.exit(json.dumps(reply))


if __name__ == "__main__":
    action, link = sys.argv[1], urllib.parse.urlsplit(sys.argv[2])
    {"enroll": enroll, "approve": approve}[action](
        f"{link.scheme}://{link.netloc}", link.path
    )
