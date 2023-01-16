from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)

import random
import string

def generate_password_reset_code():
    # generate a random string of length 10
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
