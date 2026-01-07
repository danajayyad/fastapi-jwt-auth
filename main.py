from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv
import secrets


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_db = {
    "tim":{
        "username": "tim",
        "full_name": "Tim Danny",
        "email": "tim@gmail.com",
        "hashed_password": "",
        "disabled": False
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str

class User(BaseModel):
    username: str
    email: str
    full_name: str or None=None
    disabled: bool or None=None


class UserInDB(User): # inherits from user
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password , hashed_password):
    return pwd_context.verify(plain_password,hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)  # unpacks the dictionary into keyword arguments


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False

    if not  verify_password(user.hashed_password, password):
        return False

    return user

#  generating jwt
def create_access_token(data: dict, expires_delta: timedelta or None=None):
    to_encode = data.copy() # claims to contain in the jwt
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) # The try block automatically fails and raises an exception if the token’s signature is invalid or if the token has expired, ensuring only untampered and unexpired tokens are accepted.
        username = payload.get("sub")  # payload["sub"]
        if username is None:
            raise credential_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credential_exception

    user = get_user(db, token_data.username)
    if user is None:
        return credential_exception

    return user