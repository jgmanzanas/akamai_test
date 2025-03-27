from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Depends, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlmodel import Session

from app.models import User
from app.settings import create_db_and_tables, get_session
from app.utils import PasswordHelper, AuthenticationHelper

ACCESS_TOKEN_EXPIRE_MINUTES = 30


@asynccontextmanager
async def lifespan(app_obj: FastAPI):
    # Load the DB
    create_db_and_tables()
    yield


SessionDep = Annotated[Session, Depends(get_session)]

security = HTTPBasic()

app = FastAPI(lifespan=lifespan)


@app.post("/user")
def create_user(user: User, session: SessionDep) -> User:
    user.password = PasswordHelper.hash_password(user.password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@app.get("/issue-token")
def issue_token(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)], session: SessionDep
) -> Response:
    user = AuthenticationHelper.check_user_authentication(
        session, credentials.username, credentials.password
    )
    user_token = AuthenticationHelper.generate_user_token(user.id, ACCESS_TOKEN_EXPIRE_MINUTES)
    return {'access_token': user_token}


@app.get("/validate-token")
def validate_token(
    user_token: Annotated[str, Depends(AuthenticationHelper.validate_user_token)],
    session: SessionDep
) -> Response:
    try:
        return 'success'
    except Exception as e:
        print(e)
        return 'failure'
