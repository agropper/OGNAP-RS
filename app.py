import os

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, Request, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from decouple import config


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = config("SECRET_KEY")
ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
#    user = get_user(db, username=token_data.username)
#    if user is None:
#        raise credentials_exception
#    return user
    return username


@app.get("/")
async def hello_world():
    return {"message": "Hello World"}

@app.get("/static/{path:path}")
async def get_static_file(path: str, user = Depends(get_current_user)):
  return FileResponse(os.path.join("static", path))
