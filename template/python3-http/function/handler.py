def validate_token(secret, auth_header):
    auth_token = auth_header.split(" ")[1]
    return secret == auth_token


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
        auth_header = event.headers.get("Authorization")
        if validate_token(payload_secret, auth_header):
            return {
                "status": 200,
                "body": {
                    "message": "Token validation successful. You said: " + message,
                },
            }
        else:
            return format_error(403, "Token validation failed.")
    except Exception as e:
        return format_error(500, e.__name__)
