import hmac, hashlib


def validate_hmac(message, secret, hash):
    received_hash = hash.lstrip("sha1=")
    expected_mac = hmac.new(secret.encode(), message.encode(), hashlib.sha1)
    created_hash = expected_mac.hexdigest()
    return received_hash == created_hash


def format_error(status, message):
    return {"status": status, "errors": [message]}


def handle(event, context):
    try:
        with open("/var/openfaas/secrets/payload-secret", "r") as secret_content:
            payload_secret = secret_content.read()
    except FileNotFoundError:
        return format_error(500, "Failed to read shared secret.")
    try:
        message = event.body.decode("UTF-8")
        message_mac = event.headers.get("Hmac")
        if validate_hmac(message, payload_secret, message_mac):
            return {
                "status": 200,
                "body": {
                    "message": "HMAC validation successful. You said: " + message,
                },
            }
        else:
            return format_error(403, "HMAC validation failed.")
    except Exception as e:
        return format_error(500, e.__name__)
