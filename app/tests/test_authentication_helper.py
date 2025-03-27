import uuid
import pytest
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidSubjectError
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException, status
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from app.main import app
from app.utils import (
    AuthenticationHelper, PasswordHelper, JWT_ALGORITHM
)
from app.models import User
from app.settings import get_session


@pytest.fixture(name='session')  
def session_fixture():  
    engine = create_engine(
        'sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

@pytest.fixture(name='user')
def user_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    password = PasswordHelper.hash_password('test_password')
    user = User(id=uuid.uuid4(), name='test_name', password=password)

    session.add(user)
    session.commit()
    session.refresh(user)
    yield user

    app.dependency_overrides.clear()

def test_check_user_authentication(session: Session, user: User):
    user_returned = AuthenticationHelper.check_user_authentication(
        session, 'test_name', 'test_password'
    )
    assert user == user_returned

def test_check_user_authentication_user_not_found(
    session: Session, user: User
):
    try:
        AuthenticationHelper.check_user_authentication(
            session, 'invalid_name', 'invalid_password'
        )
    except HTTPException as httpe:
        assert httpe.status_code == status.HTTP_404_NOT_FOUND
        assert httpe.detail == 'User not found'
        assert True
    except Exception:
        assert False


def test_check_user_authentication_invalid_password(
    session: Session, user: User
):
    try:
        AuthenticationHelper.check_user_authentication(
            session, 'test_name', 'invalid_password'
        )
    except HTTPException as httpe:
        assert httpe.status_code == status.HTTP_403_FORBIDDEN
        assert httpe.detail == 'Invalid authentication'
        assert True
    except Exception:
        assert False


def test_generate_user_token_without_expiration():
    user_uuid = str(uuid.uuid4())
    user_token = AuthenticationHelper.generate_user_token(user_uuid)
    
    with open('publicKey.pem', 'rb') as file:
        public_key = file.read()
    payload = jwt.decode(user_token, public_key, algorithms=[JWT_ALGORITHM])
    assert user_uuid == payload.get("sub")
    assert None == payload.get('exp')


def test_generate_user_token_with_expiration():
    user_uuid = str(uuid.uuid4())
    user_token = AuthenticationHelper.generate_user_token(user_uuid, 30)
    
    with open('publicKey.pem', 'rb') as file:
        public_key = file.read()
    payload = jwt.decode(user_token, public_key, algorithms=[JWT_ALGORITHM])
    expiration_time = datetime.now(timezone.utc) + timedelta(minutes=30)
    assert user_uuid == payload.get("sub")
    # Asserting the expiration time generated on test and the one on JWT
    # don't differ in 5 seconds or more
    assert expiration_time.timestamp() - payload.get('exp') < 5


def test_generate_user_token_with_expiration_0():
    user_uuid = str(uuid.uuid4())
    user_token = AuthenticationHelper.generate_user_token(user_uuid, 0)
    
    with open('publicKey.pem', 'rb') as file:
        public_key = file.read()
    try:
        jwt.decode(user_token, public_key, algorithms=[JWT_ALGORITHM])
        assert False
    except ExpiredSignatureError:
        assert True
    
# TODO set file as env var
#def test_generate_user_token_file_not_found():

def test_generate_user_token_invalid_data_type_subject():
    user_uuid = False
    try:
        user_token = AuthenticationHelper.generate_user_token(user_uuid)
    except Exception as e:
        assert False
    
    with open('publicKey.pem', 'rb') as file:
        public_key = file.read()
    try:
        jwt.decode(user_token, public_key, algorithms=[JWT_ALGORITHM])
        assert False
    except InvalidSubjectError:
        assert True


def test_generate_user_token_invalid_data_type_expiration():
    user_uuid = str(uuid.uuid4())
    try:
        AuthenticationHelper.generate_user_token(user_uuid, 'invalid_exp')
        assert False
    except TypeError:
        assert True

def test_validate_user_token():
    user_uuid = str(uuid.uuid4())
    user_token = AuthenticationHelper.generate_user_token(user_uuid)

    assert AuthenticationHelper.validate_user_token(user_token) == True