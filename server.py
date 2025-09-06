from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import hashlib
import secrets
import shutil
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT settings
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_HOURS = 24

# Create upload directories
UPLOAD_DIR = ROOT_DIR / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)
(UPLOAD_DIR / 'documents').mkdir(exist_ok=True)
(UPLOAD_DIR / 'products').mkdir(exist_ok=True)

# Create the main app
app = FastAPI(title="Wift Manufacturer Platform")
api_router = APIRouter(prefix="/api")

security = HTTPBearer()

# Enums
class BusinessType(str, Enum):
    MANUFACTURER = "Manufacturer"
    TRADING_COMPANY = "Trading Company"
    WHOLESALER = "Wholesaler"
    DISTRIBUTOR = "Distributor"

class ManufacturerStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

# Models
class UserSignup(BaseModel):
    email: EmailStr
    password: str
    phone: str
    company_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPVerification(BaseModel):
    phone: str
    otp: str

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    phone: str
    company_name: str
    password_hash: str
    is_verified: bool = False
    role: str = "manufacturer"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CompanyProfile(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    company_name: str
    business_type: BusinessType
    year_established: int
    num_employees: str
    factory_size: str
    certifications: List[str] = []
    address: str
    city: str
    state: str
    country: str
    postal_code: str
    contact_person: str
    contact_role: str
    gst_number: Optional[str] = None
    status: ManufacturerStatus = ManufacturerStatus.PENDING
    documents: List[dict] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Product(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    name: str
    category: str
    description: str
    images: List[str] = []
    moq: str
    production_capacity: str
    price_range: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Helper functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash

def create_jwt_token(user_data: dict) -> str:
    payload = {
        'user_id': user_data['id'],
        'email': user_data['email'],
        'role': user_data['role'],
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def generate_mock_otp(phone: str) -> str:
    # For mock OTP, we'll use last 4 digits of phone or 1234
    return phone[-4:] if len(phone) >= 4 else "1234"

# Routes
@api_router.get("/")
async def root():
    return {"message": "Wift Manufacturer Platform API"}

@api_router.post("/auth/signup")
async def signup(user_data: UserSignup):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email,
        phone=user_data.phone,
        company_name=user_data.company_name,
        password_hash=hash_password(user_data.password)
    )
    
    user_dict = user.dict()
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    await db.users.insert_one(user_dict)
    
    # Generate mock OTP
    mock_otp = generate_mock_otp(user_data.phone)
    
    return {
        "message": "User registered successfully",
        "user_id": user.id,
        "mock_otp": mock_otp,  # In production, this would be sent via SMS
        "phone": user_data.phone
    }

@api_router.post("/auth/verify-otp")
async def verify_otp(otp_data: OTPVerification):
    expected_otp = generate_mock_otp(otp_data.phone)
    
    if otp_data.otp != expected_otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Find and verify user
    user = await db.users.find_one({"phone": otp_data.phone})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Mark as verified
    await db.users.update_one(
        {"phone": otp_data.phone},
        {"$set": {"is_verified": True}}
    )
    
    # Create JWT token
    token = create_jwt_token(user)
    
    return {
        "message": "Phone verified successfully",
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "company_name": user["company_name"],
            "role": user["role"]
        }
    }

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    user = await db.users.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.get("is_verified", False):
        raise HTTPException(status_code=401, detail="Phone number not verified")
    
    token = create_jwt_token(user)
    
    return {
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "company_name": user["company_name"],
            "role": user["role"]
        }
    }

@api_router.get("/auth/me")
async def get_current_user(payload: dict = Depends(verify_jwt_token)):
    user = await db.users.find_one({"id": payload["user_id"]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user["id"],
        "email": user["email"],
        "company_name": user["company_name"],
        "role": user["role"],
        "is_verified": user.get("is_verified", False)
    }

@api_router.post("/company/profile")
async def create_company_profile(
    company_name: str = Form(...),
    business_type: BusinessType = Form(...),
    year_established: int = Form(...),
    num_employees: str = Form(...),
    factory_size: str = Form(...),
    address: str = Form(...),
    city: str = Form(...),
    state: str = Form(...),
    country: str = Form(...),
    postal_code: str = Form(...),
    contact_person: str = Form(...),
    contact_role: str = Form(...),
    gst_number: str = Form(None),
    certifications: str = Form(""),
    documents: List[UploadFile] = File(default=[]),
    payload: dict = Depends(verify_jwt_token)
):
    # Check if profile already exists
    existing_profile = await db.company_profiles.find_one({"user_id": payload["user_id"]})
    if existing_profile:
        raise HTTPException(status_code=400, detail="Company profile already exists. Use PUT to update.")
    
    # Parse certifications
    cert_list = [cert.strip() for cert in certifications.split(',') if cert.strip()]
    
    # Handle document uploads
    uploaded_documents = []
    if documents:
        for document in documents:
            if document.filename:
                # Create unique filename
                file_extension = document.filename.split('.')[-1]
                unique_filename = f"{payload['user_id']}_{int(datetime.now(timezone.utc).timestamp())}_{document.filename}"
                file_path = UPLOAD_DIR / 'documents' / unique_filename
                
                # Save file
                with open(file_path, "wb") as buffer:
                    shutil.copyfileobj(document.file, buffer)
                
                uploaded_documents.append({
                    "filename": document.filename,
                    "stored_filename": unique_filename,
                    "file_path": str(file_path),
                    "upload_date": datetime.now(timezone.utc).isoformat(),
                    "file_size": file_path.stat().st_size
                })
    
    profile = CompanyProfile(
        user_id=payload["user_id"],
        company_name=company_name,
        business_type=business_type,
        year_established=year_established,
        num_employees=num_employees,
        factory_size=factory_size,
        certifications=cert_list,
        address=address,
        city=city,
        state=state,
        country=country,
        postal_code=postal_code,
        contact_person=contact_person,
        contact_role=contact_role,
        gst_number=gst_number,
        documents=uploaded_documents
    )
    
    profile_dict = profile.dict()
    profile_dict['created_at'] = profile_dict['created_at'].isoformat()
    await db.company_profiles.insert_one(profile_dict)
    
    return {
        "message": "Company profile created successfully", 
        "profile_id": profile.id,
        "documents_uploaded": len(uploaded_documents)
    }

@api_router.put("/company/profile")
async def update_company_profile(
    company_name: str = Form(...),
    business_type: BusinessType = Form(...),
    year_established: int = Form(...),
    num_employees: str = Form(...),
    factory_size: str = Form(...),
    address: str = Form(...),
    city: str = Form(...),
    state: str = Form(...),
    country: str = Form(...),
    postal_code: str = Form(...),
    contact_person: str = Form(...),
    contact_role: str = Form(...),
    gst_number: str = Form(None),
    certifications: str = Form(""),
    documents: List[UploadFile] = File(default=[]),
    payload: dict = Depends(verify_jwt_token)
):
    # Parse certifications
    cert_list = [cert.strip() for cert in certifications.split(',') if cert.strip()]
    
    # Handle new document uploads
    uploaded_documents = []
    if documents:
        for document in documents:
            if document.filename:
                file_extension = document.filename.split('.')[-1]
                unique_filename = f"{payload['user_id']}_{int(datetime.now(timezone.utc).timestamp())}_{document.filename}"
                file_path = UPLOAD_DIR / 'documents' / unique_filename
                
                with open(file_path, "wb") as buffer:
                    shutil.copyfileobj(document.file, buffer)
                
                uploaded_documents.append({
                    "filename": document.filename,
                    "stored_filename": unique_filename,
                    "file_path": str(file_path),
                    "upload_date": datetime.now(timezone.utc).isoformat(),
                    "file_size": file_path.stat().st_size
                })
    
    # Get existing documents
    existing_profile = await db.company_profiles.find_one({"user_id": payload["user_id"]})
    existing_documents = existing_profile.get("documents", []) if existing_profile else []
    
    # Combine existing and new documents
    all_documents = existing_documents + uploaded_documents
    
    update_data = {
        "company_name": company_name,
        "business_type": business_type,
        "year_established": year_established,
        "num_employees": num_employees,
        "factory_size": factory_size,
        "certifications": cert_list,
        "address": address,
        "city": city,
        "state": state,
        "country": country,
        "postal_code": postal_code,
        "contact_person": contact_person,
        "contact_role": contact_role,
        "gst_number": gst_number,
        "documents": all_documents,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    result = await db.company_profiles.update_one(
        {"user_id": payload["user_id"]},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Company profile not found")
    
    return {
        "message": "Company profile updated successfully",
        "documents_uploaded": len(uploaded_documents),
        "total_documents": len(all_documents)
    }

@api_router.delete("/company/profile/document/{document_filename}")
async def delete_document(
    document_filename: str,
    payload: dict = Depends(verify_jwt_token)
):
    """Delete a specific document from company profile"""
    profile = await db.company_profiles.find_one({"user_id": payload["user_id"]})
    if not profile:
        raise HTTPException(status_code=404, detail="Company profile not found")
    
    # Find and remove document
    documents = profile.get("documents", [])
    updated_documents = []
    document_found = False
    
    for doc in documents:
        if doc.get("stored_filename") == document_filename:
            document_found = True
            # Delete physical file
            try:
                file_path = Path(doc.get("file_path", ""))
                if file_path.exists():
                    file_path.unlink()
            except Exception as e:
                print(f"Error deleting file: {e}")
        else:
            updated_documents.append(doc)
    
    if not document_found:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Update profile
    await db.company_profiles.update_one(
        {"user_id": payload["user_id"]},
        {"$set": {"documents": updated_documents}}
    )
    
    return {"message": "Document deleted successfully"}

@api_router.get("/company/profile")
async def get_company_profile(payload: dict = Depends(verify_jwt_token)):
    profile = await db.company_profiles.find_one({"user_id": payload["user_id"]})
    return profile

@api_router.post("/products")
async def create_product(
    name: str = Form(...),
    category: str = Form(...),
    description: str = Form(...),
    moq: str = Form(...),
    production_capacity: str = Form(...),
    price_range: str = Form(None),
    payload: dict = Depends(verify_jwt_token)
):
    product = Product(
        user_id=payload["user_id"],
        name=name,
        category=category,
        description=description,
        moq=moq,
        production_capacity=production_capacity,
        price_range=price_range
    )
    
    product_dict = product.dict()
    product_dict['created_at'] = product_dict['created_at'].isoformat()
    await db.products.insert_one(product_dict)
    
    return {"message": "Product created successfully", "product_id": product.id}

@api_router.get("/products")
async def get_products(payload: dict = Depends(verify_jwt_token)):
    products = await db.products.find({"user_id": payload["user_id"]}).to_list(100)
    return products

@api_router.get("/admin/manufacturers")
async def get_all_manufacturers(payload: dict = Depends(verify_jwt_token)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    profiles = await db.company_profiles.find().to_list(100)
    return profiles

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()