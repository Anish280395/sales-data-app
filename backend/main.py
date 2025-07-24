from fastapi import FastAPI, Depends, HTTPException, status, Query, Body
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import os
import uuid
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

app = FastAPI()
origins = [
    "http://localhost",
    "http://localhost:5500",
    "http://127.0.0.1",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

fake_users_db = {
    "anish": {
        "username": "anish",
        "hashed_password": pwd_context.hash("anish123"),
    },
    "Rohan": {
        "username": "Rohan001",
        "hashed_password": pwd_context.hash("Rohan123"),
    },
}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str):
    user = fake_users_db.get(username)
    return user

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user['hashed_password']):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['username']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


FILE_DIR = "generated_files"
os.makedirs(FILE_DIR, exist_ok=True)

def load_product_data() -> pd.DataFrame:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(base_dir, "..", "product_data.csv")
    return pd.read_csv(csv_path)

@app.get("/")
async def root():
    return {"message": "Welcome to Sales Data API. Use /token to login."}

@app.get("/search")
async def search_products(q: str = Query(..., min_length=1), current_user: dict = Depends(get_current_user)):
    df = load_product_data()
    filtered = df[
        df["material_number"].str.contains(q, case=False) |
        df["material_description"].str.contains(q, case=False)
    ]
    results = filtered.to_dict(orient="records")
    return {"results": results}

@app.post("/generate")
async def generate_excel(
    data: dict = Body(...),
    current_user: dict = Depends(get_current_user)
):
    material_number = data.get("material_number")
    fields: List[str] = data.get("fields", [])
    
    if not material_number or not fields:
        raise HTTPException(
            status_code=400, detail="Material number and fields are required."
        )
        
    df = load_product_data()
    filtered = df[df["material_number"] == material_number]
        
    if filtered.empty:
        raise HTTPException(
            status_code=404, detail="Material number not found."
        )
        
    filtered = filtered[fields]
    
    file_id = str(uuid.uuid4())
    filename = f"product_data_{file_id}.xlsx"
    file_path = os.path.join(FILE_DIR, filename)
    filtered.to_excel(file_path, index=False)
    
    return {"message": "file generated", "download_url": f"/download/{filename}"}

@app.get("/download/{filename}")
async def download_file(filename: str, current_user: dict = Depends(get_current_user)):
    file_path = os.path.join(FILE_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', filename=filename)
