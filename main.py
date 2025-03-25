import jwt
from typing import Annotated
from contextlib import asynccontextmanager

from fastapi import FastAPI, Body, Depends, Response
from sqlmodel import Session

from models import User
from settings import create_db_and_tables, get_session
from utils import check_user_authentication, generate_user_token, validate_user_token

ACCESS_TOKEN_EXPIRE_MINUTES = 30

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the DB
    create_db_and_tables()
    yield


SessionDep = Annotated[Session, Depends(get_session)]

app = FastAPI(lifespan=lifespan)

@app.post("/user")
def create_user(user: User, session: SessionDep) -> User:
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@app.post("/issue-token")
def issue_token(user: Annotated[User, Body], session: SessionDep) -> Response:
    user = check_user_authentication(session, user.name. user.password)
    user_token = generate_user_token(user.id, user.name, ACCESS_TOKEN_EXPIRE_MINUTES)
    return {'token': user_token}
    

@app.post("/validate-token")
def validate_token(user_token: Annotated[str, Body(embed=True)], session: SessionDep) -> Response:
    try:
        validate_user_token(session, user_token)
        return 'success'
    except Exception as e:
        print(e)
        return 'failure'