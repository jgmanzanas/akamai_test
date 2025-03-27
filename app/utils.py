import logging
from typing import Annotated, Literal
from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select, text
from passlib.context import CryptContext

from app.models import User

JWT_ALGORITHM = 'RS256'

logger = logging.getLogger(__name__)

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class PasswordHelper:
    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool | Exception:
        return password_context.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str | Exception:
        return password_context.hash(password)


class AuthenticationHelper:
    @classmethod
    def check_user_authentication(
        cls, session: Session, username: str, password: str
    ) -> User | HTTPException:
        user = session.exec(select(User).where(text(f'name="{username}"'))).one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not PasswordHelper.verify_password(password, user.password):
            raise HTTPException(status_code=403, detail="Invalid authentication")
        user.model_dump()
        return user

    @classmethod
    def generate_user_token(
        cls, user_uuid: str, expires_in: timedelta | None = None
    ) -> str | Exception:
        data_to_encode = {'sub': user_uuid}
        if expires_in:
            expiration_time = datetime.now(timezone.utc) + expires_in
            data_to_encode.update({"exp": expiration_time})
        try:
            with open('privateKey.pem', 'rb') as file:
                private_key = file.read()
            return jwt.encode(data_to_encode, private_key, algorithm=JWT_ALGORITHM)
        except FileNotFoundError as fnfe:
            logger.error('Private Key file does not exists.')
            raise fnfe
        except OSError as ose:
            logger.error(f'Unexpected exception while reading the Private key file: {str(ose)}')
            raise ose
        except TypeError as te:
            logger.error('Invalid data to encode JWT')
            raise te

    @classmethod
    def validate_user_token(
        cls, user_token: Annotated[str, Depends(oauth2_scheme)]
    ) -> Literal[True] | HTTPException:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            with open('publicKey.pem', 'rb') as file:
                public_key = file.read()
            payload = jwt.decode(user_token, public_key, algorithms=[JWT_ALGORITHM])
            user_uuid = payload.get("sub")
            if user_uuid is None:
                raise credentials_exception
        except ExpiredSignatureError as ese:
            logger.error('Expired access token. Please, request a new one.')
            raise credentials_exception from ese
        except InvalidTokenError as ite:
            logger.error('Invalid token format or structure.')
            raise credentials_exception from ite
        return True
