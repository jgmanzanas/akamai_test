import jwt
from jwt.exceptions import InvalidTokenError
from typing import Annotated
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select, text
from passlib.context import CryptContext

from models import User

JWT_ALGORITHM = 'RS256'

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return password_context.verify(plain_password, hashed_password)

def hash_password(password):
    return password_context.hash(password)

def check_user_authentication(session: Session, username: str, password: str):
    # user = get_user(fake_db, username)
    user = session.exec(select(User).where(text(f'name="{username}"'))).one_or_none()
    user.model_dump()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(password, user.password):
        raise HTTPException(status_code=403, detail="Invalid authentication")
    return user

def generate_user_token(sub: str, username: str, expires_in: timedelta | None = None):
    data_to_encode = {'sub': sub, 'user': username}
    if expires_in:
        expiration_time = datetime.now(timezone.utc) + expires_in
        data_to_encode.update({"exp": expiration_time})
    with open('privateKey.pem', 'rb') as file:
        private_key = file.read()
    return jwt.encode(data_to_encode, private_key, algorithm=JWT_ALGORITHM)

def validate_user_token(session: Session, user_token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        with open('publicKey.pem', 'rb') as file:
            public_key = file.read()
        payload = jwt.decode(user_token, public_key, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        username = payload.get("user")
        if username is None and user_id is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = session.exec(select(User).where(text(f'name="{username}"'))).one_or_none()
    if user is None:
        raise credentials_exception
    return True