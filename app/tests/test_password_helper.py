from fastapi.testclient import TestClient

from app.main import app
from app.utils import PasswordHelper

client = TestClient(app)


def test_hash_password_str():
    plain_pwd = 'test_password'
    try:
        PasswordHelper.hash_password(plain_pwd)
        assert True
    except Exception:
        assert False

def test_hash_password_bytes():
    plain_pwd = b'test_password'
    try:
        PasswordHelper.hash_password(plain_pwd)
        assert True
    except Exception:
        assert False


def test_hash_password_not_str():
    invalid_plain_pwd = True
    try:
        PasswordHelper.hash_password(invalid_plain_pwd)
    except TypeError:
        assert True
    except Exception as e:
        assert False

def test_verify_password():
    plain_pwd = 'test_password'
    hashed_pwd = PasswordHelper.hash_password(plain_pwd)
    assert PasswordHelper.verify_password(plain_pwd, hashed_pwd) == True
    assert PasswordHelper.verify_password('invalid_pwd', hashed_pwd) == False


def test_verify_password_not_str():
    plain_pwd = 'test_password'
    hashed_pwd = PasswordHelper.hash_password(plain_pwd)
    try:
        PasswordHelper.verify_password(False, hashed_pwd)
    except TypeError:
        assert True
    except Exception:
        assert False
