import os, hmac, hashlib


def validate_hmac(message, secret, hash):
    received_hash = hash.lstrip("sha1=")
    expected_mac = hmac.new(secret.encode(), message.encode(), hashlib.sha1)
    created_hash = expected_mac.hexdigest()
    return received_hash == created_hash


def handle(req):
    try:
        with open("/var/openfaas/secrets/payload-secret", "r") as secret_content:
            payload_secret = secret_content.read()
    except FileNotFoundError:
        return "Failed to read shared secret."

    try:
        message_mac = os.getenv("Http_Hmac")
        if validate_hmac(req, payload_secret, message_mac):
            return "Successfully validated: " + req
        else:
            return "HMAC validation failed."
    except Exception as e:
        return e.__name__
