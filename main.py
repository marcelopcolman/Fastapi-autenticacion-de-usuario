from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Union
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW", ## secret
        "disabled": False,
    }
}

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer("/token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "51240170810f43797118384a67cc7c59527171e9a248b20633f5d32668fb7672"
ALGORITHM = "HS256"

class User(BaseModel):
    username: str
    full_name: Union[str, None] = None
    email: Union[str, None] = None
    disabled: Union[bool, None] = None

class UserInDB(User):
    hashed_password: str


def get_user(db, username):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)
    return []

def verify_password(plane_password, hashed_password):
    return pwd_context.verify(plane_password, hashed_password)



def authenticate_user(db, username, password):
    user = get_user(db, username)
    if not user:
        raise HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    return user

def create_token(data:dict, time_expire: Union[datetime, None] = None ):
    data_copy = data.copy()
    if time_expire is None:
        expires = datetime.utcnow() + timedelta(minutes=30)
    else:
        expires = datetime.utcnow() + time_expire
    data_copy.update({"exp": expires})
    token_jwt = jwt.encode(data_copy, key=SECRET_KEY, algorithm=ALGORITHM)
    return token_jwt

def get_user_current(token: str = Depends(oauth2_scheme)):
    try:
        token_decode = jwt.decode(token, key=SECRET_KEY, algorithms=[ALGORITHM])
        username = token_decode.get("sub")
        if username == None:
            raise HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})

    user = get_user(fake_users_db, username)
    if not user:
        raise HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    return user

def get_user_disabled_current(user: User = Depends(get_user_current)):
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive User")
    return user


#@app.get("/")
#def root():
#    return "Hi I am FastApi"

#@app.get("/users/me")
#def user(user: User = Depends(get_user_disabled_current)):
#    return user

#@app.post("/token")
#def login(form_data: OAuth2PasswordRequestForm = Depends()):
#    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
#    access_token_expires = timedelta(minutes=30)
#    access_token_jwt = create_token({"sub": user.username}, access_token_expires)
#    return {
#        "access_token": access_token_jwt,
#        "token_type": "bearer"
#    }


@app.get("/")
async def root(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/user/me")
async def user(request: Request, user: User = Depends(get_user_disabled_current)):
    return templates.TemplateResponse("user.html", {"request": request, "user": user})

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    access_token_expires = timedelta(minutes=30)
    access_token_jwt = create_token({"sub": user.username}, access_token_expires)
    return {"access_token": access_token_jwt,"token_type": "bearer"}
    