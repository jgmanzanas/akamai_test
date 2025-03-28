import os
import jwt
import logging
import base64
from typing import Annotated, Literal
from datetime import datetime, timedelta, timezone

from ansible_vault import Vault
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select, text
from passlib.context import CryptContext

from app.models import User

JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM')
PUBLIC_KEY_FILE_PATH = os.environ.get('PUBLIC_FILE_PATH')
PRIVATE_KEY_FILE_PATH = os.environ.get('PRIVATE_FILE_PATH')
with open(os.environ.get('VAULT_FILE_PATH'), 'r') as file:
    VAULT_KEY = base64.b64decode(file.read()).decode("utf-8")

logger = logging.getLogger(__name__)

password_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
vault = Vault(VAULT_KEY)


class PasswordHelper:
    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool | Exception:
        try:
            return password_context.verify(plain_password, hashed_password)
        except TypeError as ese:
            logger.error(f'Exception while verifying the password: {str(ese)}')
            raise ese

    @classmethod
    def hash_password(cls, password: str) -> str | Exception:
        try:
            return password_context.hash(password)
        except TypeError as ese:
            logger.error(f'Exception while hashing the password: {str(ese)}')
            raise ese

class AuthenticationHelper:
    @classmethod
    def check_user_authentication(
        cls, session: Session, username: str, password: str
    ) -> User | HTTPException:
        user = session.exec(select(User).where(text(f'name="{username}"'))).one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail='User not found'
            )
        if not PasswordHelper.verify_password(password, user.password):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail='Invalid authentication'
            )
        user.model_dump()
        return user

    @classmethod
    def generate_user_token(
        cls, sub: str, expires_in: int | None = None
    ) -> str | FileNotFoundError | OSError | TypeError:
        data_to_encode = {'sub': sub}
        try:
            if expires_in is not None:
                expiration_time = datetime.now(timezone.utc) + timedelta(minutes=expires_in)
                data_to_encode.update({'exp': expiration_time})
            with open(PRIVATE_KEY_FILE_PATH, 'rb') as file:
                encrypted_key = file.read()
                private_key = vault.load_raw(encrypted_key)
                logger.info(f'private key\n {private_key}')
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
    ) -> Literal[True] | HTTPException | FileNotFoundError | OSError:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentials',
            headers={'WWW-Authenticate': 'Bearer'},
        )
        try:
            with open(PUBLIC_KEY_FILE_PATH, 'rb') as file:
                encrypted_key = file.read()
                public_key = vault.load_raw(encrypted_key)
            payload = jwt.decode(user_token, public_key, algorithms=[JWT_ALGORITHM])
            user_uuid = payload.get("sub")
            if user_uuid is None:
                raise credentials_exception
        except ExpiredSignatureError as ese:
            logger.error('Expired access token. Please, request a new one.')
            raise credentials_exception from ese
        except InvalidTokenError as ite:
            logger.error('Invalid token format, structure or algorithm.')
            raise credentials_exception from ite
        except FileNotFoundError as fnfe:
            logger.error('Private Key file does not exists.')
            raise fnfe
        except OSError as ose:
            logger.error(f'Unexpected exception while reading the Private key file: {str(ose)}')
            raise ose       
        return True
