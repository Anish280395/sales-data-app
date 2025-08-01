from fastapi import FastAPI, Depends, HTTPException, status, Query, Body, File, UploadFile
from fastapi.responses import FileResponse, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, validator
import pandas as pd
import os
import uuid
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from io import BytesIO
import random

app = FastAPI()

# CORS for GitHub Pages access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://anish280395.github.io"],
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
    "anish@skf.com": {
        "username": "anish@skf.com",
        "hashed_password": "$2b$12$kDPbwvWm0OecKMjSL/mC4.8Fmjz0S3nHLPojAPV0UQLGmZyQU0dJK",
    },
    "rohan@skf.com": {
        "username": "rohan@skf.com",
        "hashed_password": "$2b$12$5gyn35wEOPKZkAXY0a5kN.dTuNB8vWD.2FcB7yKIVnWivPwnnN7JK",
    },
}

class SignupRequest(BaseModel):
    email: EmailStr
    password: str

    @validator('email')
    def validate_skf_email(cls, v):
        if not v.endswith('@skf.com'):
            raise ValueError('Email must be an @skf.com address')
        return v.lower()

    @validator('password')
    def password_length(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        return v

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str):
    user = fake_users_db.get(username.lower())
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

@app.post("/signup")
async def signup(data: SignupRequest):
    email = data.email
    if email in fake_users_db:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = pwd_context.hash(data.password)
    fake_users_db[email] = {"username": email, "hashed_password": hashed_password}

    return {"message": "Signup successful"}

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
    generated_dir = os.path.join(base_dir, "generated_files")
    os.makedirs(generated_dir, exist_ok=True)
    csv_path = os.path.join(generated_dir, "product_data_100.csv")

    if not os.path.exists(csv_path):
        countries = ["Germany", "France", "Italy", "Spain", "Netherlands", "Sweden", "Poland"]
        brands = ["BrandA", "BrandB", "BrandC", "BrandX"]
        dimensions = ["10x5x2", "15x10x5", "20x10x5", "5x5x5"]
        products = []
        for i in range(1, 101):
            products.append({
                "material_number": f"MAT{str(i).zfill(3)}",
                "article_number": f"ART{str(i).zfill(3)}",
                "article_name": f"Sample Product {i}",
                "article_group_assignment": random.choice(["Electronics", "Hardware"]),
                "weight": round(random.uniform(1.0, 150.0), 2),
                "customs_tariff_number": f"{random.randint(10000000, 99999999)}",
                "country_of_origin": random.choice(countries),
                "purchase_price": round(random.uniform(10.0, 500.0), 2),
                "purchase_price_unit": "EUR",
                "predecessor_successor_article": None,
                "descriptive_texts": "Auto-generated product entry.",
                "product_image": f"product_image_{i}.jpg",
                "article_dimensions": random.choice(dimensions),
                "article_dimensions_unit": "cm",
                "brand": random.choice(brands),
                "ROHS": random.choice(["Yes", "No"]),
                "REACH": random.choice(["Yes", "No"]),
            })
        df = pd.DataFrame(products)
        df.to_csv(csv_path, index=False)
    else:
        df = pd.read_csv(csv_path)

    return df

@app.get("/")
async def root():
    return {"message": "Welcome to Sales Data API. Use /token to login."}

@app.get("/search")
async def search_products(q: str = Query(..., min_length=1), current_user: dict = Depends(get_current_user)):
    df = load_product_data()
    terms = [term.strip() for term in q.split(",")]
    mask = df["material_number"].str.contains('|'.join(terms), case=False, na=False) | \
           df["article_name"].str.contains('|'.join(terms), case=False, na=False)
    filtered = df[mask].fillna("")
    results = filtered.to_dict(orient="records")
    return results

@app.post("/generate")
async def generate_excel(
    data: dict = Body(...),
    current_user: dict = Depends(get_current_user)):
    material_numbers: List[str] = data.get("material_numbers", [])
    fields: List[str] = data.get("fields", [])

    if not material_numbers or not fields:
        raise HTTPException(status_code=400, detail="Material numbers and fields are required.")

    df = load_product_data()
    filtered = df[df["material_number"].isin(material_numbers)]

    if filtered.empty:
        raise HTTPException(status_code=404, detail="None of the material numbers found.")

    valid_fields = [field for field in fields if field in df.columns]
    filtered = filtered[valid_fields]

    file_id = str(uuid.uuid4())
    filename = f"product_data_{file_id}.xlsx"
    file_path = os.path.join(FILE_DIR, filename)
    filtered.to_excel(file_path, index=False)

    return {"message": "file generated", "download_url": f"/download/{filename}"}

@app.get("/download/{filename}")
async def download_file(filename: str):
    file_path = os.path.join(FILE_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', filename=filename)

@app.post("/import-excel")
async def import_excel(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    if not file.filename.endswith((".xlsx", ".xls")):
        raise HTTPException(status_code=400, detail="Only Excel files are supported.")

    contents = await file.read()
    uploaded_df = pd.read_excel(BytesIO(contents))

    if "material_number" not in uploaded_df.columns:
        raise HTTPException(status_code=400, detail="Missing 'material_number' column in Excel.")

    uploaded_df["material_number"] = uploaded_df["material_number"].astype(str).str.strip()
    valid_df = load_product_data()
    valid_df["material_number"] = valid_df["material_number"].astype(str).str.strip()

    merged = pd.merge(uploaded_df, valid_df, on="material_number", how="left", suffixes=('', '_matched'))

    matched = merged[~merged["article_number"].isna()]
    unmatched = merged[merged["article_number"].isna()][["material_number"]]

    return {
        "matched": matched.fillna("").to_dict(orient="records"),
        "unmatched": unmatched["material_number"].tolist()
    }

@app.get("/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"]}

@app.post("/generate-from-upload")
async def generate_from_upload(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    df_uploaded = pd.read_excel(BytesIO(await file.read()))
    if 'material_number' not in df_uploaded.columns:
        raise HTTPException(status_code=400, detail="Excel must contain 'material_number' column")

    df = load_product_data()
    uploaded_materials = df_uploaded['material_number'].dropna().astype(str).str.strip().tolist()
    matched = df[df['material_number'].isin(uploaded_materials)]

    if matched.empty:
        raise HTTPException(status_code=404, detail="No matching material numbers found.")

    filename = f"product_data_from_upload_{uuid.uuid4()}.xlsx"
    filepath = os.path.join(FILE_DIR, filename)
    matched.to_excel(filepath, index=False)

    return {"message": "Excel generated from upload", "download_url": f"/download/{filename}"}

@app.get("/health")
def health():
    return {"status": "ok"}
