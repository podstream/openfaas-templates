import os


def validate_token(secret, auth_header):
    auth_token = auth_header.split(" ")[1]
    return secret == auth_token


def handle(req):
    try:
        with open("/var/openfaas/secrets/payload-secret", "r") as secret_content:
            payload_secret = secret_content.read()
    except FileNotFoundError:
        return "Failed to read shared secret."

    try:
        auth_header = os.getenv("Http_Authorizaton")
        if validate_token(payload_secret, auth_header):
            return "Successfully validated: " + req
        else:
            return "Token validation failed."
    except Exception as e:
        return e.__name__
