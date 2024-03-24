import bcrypt


def make_password(password: bytes) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password, salt).decode()
    return hashed_password


def check_password(password: str, hashed_password: str) -> bool:
    password = password.encode()
    hashed_password = hashed_password.encode()
    return bcrypt.checkpw(password, hashed_password)
