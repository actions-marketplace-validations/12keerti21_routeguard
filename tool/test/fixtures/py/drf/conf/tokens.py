import jwt


def is_jwt_formatted(token):
    try:
        jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return False
    return True
