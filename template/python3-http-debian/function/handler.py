import hmac, hashlib


def validate_hmac(message, secret, hash):
    received_hash = hash.lstrip("sha1=")

    expected_mac = hmac.new(secret.encode(), message.encode(), hashlib.sha1)
    created_hash = expected_mac.hexdigest()

    return received_hash == created_hash


def handle(event, context):
    try:
        with open("/var/openfaas/secrets/payload-secret", "r") as secret_content:
            payload_secret = secret_content.read()
    except FileNotFoundError:
        return {
            "statusCode": 500,
            "body": {"message": "Failed to read shared secret."},
        }
    try:
        message = event.body.decode("UTF-8")
        message_mac = event.headers.get("Hmac")
        if validate_hmac(message, payload_secret, message_mac):
            return {
                "statusCode": 200,
                "body": {
                    "message": "Successfully validated. You said: " + message,
                },
            }
        else:
            return {
                "statusCode": 403,
                "body": {
                    "message": "HMAC validation failed.",
                },
            }
    except:
        return {
            "statusCode": 403,
            "body": {
                "message": "HMAC validation failed, unknown error.",
            },
        }
