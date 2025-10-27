import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import bcrypt
import jwt
from bson import ObjectId
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import User as UserSchema, Role as RoleSchema, Post as PostSchema

APP_NAME = "Sentra"
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = "HS256"
TOKEN_EXPIRE_MINUTES = 60 * 24

app = FastAPI(title=f"{APP_NAME} API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# Utilities

def oid(s: str) -> ObjectId:
    try:
        return ObjectId(s)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")


def to_public(doc: dict) -> dict:
    if not doc:
        return doc
    d = doc.copy()
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    if "password_hash" in d:
        d.pop("password_hash", None)
    return d


def create_token(user: dict) -> str:
    payload = {
        "sub": str(user["_id"]),
        "email": user.get("email"),
        "role_id": str(user.get("role_id") or ""),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


async def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        user = db["user"].find_one({"_id": oid(user_id)})
        if not user or not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="Inactive or missing user")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_permission(perm: str):
    async def _dep(user: dict = Depends(get_current_user)) -> dict:
        role_id = user.get("role_id")
        if not role_id:
            raise HTTPException(status_code=403, detail="No role assigned")
        role = db["role"].find_one({"_id": oid(role_id)})
        if not role:
            raise HTTPException(status_code=403, detail="Role not found")
        if perm not in role.get("permissions", []):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return _dep


# Request/Response models
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    token: str


class UpdateUserRole(BaseModel):
    role_id: str


class PostCreate(BaseModel):
    title: str
    content: str = ""
    status: str = "Draft"


class PostUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    status: Optional[str] = None


class RoleCreate(BaseModel):
    name: str
    permissions: List[str] = []


# Seed default roles and admin user
@app.on_event("startup")
def seed_defaults():
    if db is None:
        return
    # Roles
    existing_roles = {r["name"]: r for r in db["role"].find({})}
    defaults = {
        "Admin": ["create", "edit", "delete", "publish", "manage_users", "manage_roles"],
        "Editor": ["create", "edit", "publish"],
        "Viewer": [],
    }
    for name, perms in defaults.items():
        if name not in existing_roles:
            create_document("role", RoleSchema(name=name, permissions=perms))
    # Admin user
    admin_email = os.getenv("ADMIN_EMAIL", "admin@sentra.dev")
    admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
    if not db["user"].find_one({"email": admin_email}):
        admin_role = db["role"].find_one({"name": "Admin"})
        pw_hash = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt()).decode()
        create_document(
            "user",
            UserSchema(
                name="Admin",
                email=admin_email,
                password_hash=pw_hash,
                role_id=str(admin_role["_id"]) if admin_role else None,
                is_active=True,
            ),
        )


@app.get("/")
def root():
    return {"message": f"{APP_NAME} API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available" if db is None else "✅ Connected",
    }
    if db is not None:
        try:
            response["collections"] = db.list_collection_names()
        except Exception as e:
            response["database"] = f"⚠️ {str(e)[:80]}"
    return response


# Auth endpoints
@app.post("/auth/signup", response_model=TokenResponse)
def signup(payload: SignupRequest):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(400, detail="Email already registered")
    # default role Viewer
    viewer = db["role"].find_one({"name": "Viewer"})
    pw_hash = bcrypt.hashpw(payload.password.encode(), bcrypt.gensalt()).decode()
    user_schema = UserSchema(
        name=payload.name,
        email=payload.email,
        password_hash=pw_hash,
        role_id=str(viewer["_id"]) if viewer else None,
        is_active=True,
    )
    inserted_id = create_document("user", user_schema)
    user = db["user"].find_one({"_id": oid(inserted_id)})
    token = create_token(user)
    return {"token": token}


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(401, detail="Invalid credentials")
    if not bcrypt.checkpw(payload.password.encode(), user["password_hash"].encode()):
        raise HTTPException(401, detail="Invalid credentials")
    token = create_token(user)
    return {"token": token}


@app.get("/me")
def me(user: dict = Depends(get_current_user)):
    # include role name and permissions
    role = None
    role_id = user.get("role_id")
    if role_id:
        role = db["role"].find_one({"_id": oid(role_id)})
    data = to_public(user)
    data["role"] = to_public(role) if role else None
    return data


# Users endpoints (admin only)
@app.get("/users")
def list_users(_: dict = Depends(require_permission("manage_users"))):
    users = [to_public(u) for u in db["user"].find({}).sort("created_at", -1)]
    return users


@app.patch("/users/{user_id}/role")
def update_user_role(user_id: str, payload: UpdateUserRole, _: dict = Depends(require_permission("manage_users"))):
    role = db["role"].find_one({"_id": oid(payload.role_id)})
    if not role:
        raise HTTPException(404, detail="Role not found")
    db["user"].update_one({"_id": oid(user_id)}, {"$set": {"role_id": str(role["_id"]), "updated_at": datetime.now(timezone.utc)}})
    user = db["user"].find_one({"_id": oid(user_id)})
    return to_public(user)


# Roles endpoints (admin only)
@app.get("/roles")
def list_roles(_: dict = Depends(get_current_user)):
    # Anyone authenticated can read roles for UI; permission checks happen for mutations
    return [to_public(r) for r in db["role"].find({}).sort("name", 1)]


@app.post("/roles")
def create_role(payload: RoleCreate, _: dict = Depends(require_permission("manage_roles"))):
    rid = create_document("role", RoleSchema(name=payload.name, permissions=payload.permissions))
    role = db["role"].find_one({"_id": oid(rid)})
    return to_public(role)


@app.patch("/roles/{role_id}")
def update_role(role_id: str, payload: RoleCreate, _: dict = Depends(require_permission("manage_roles"))):
    db["role"].update_one({"_id": oid(role_id)}, {"$set": {"name": payload.name, "permissions": payload.permissions, "updated_at": datetime.now(timezone.utc)}})
    role = db["role"].find_one({"_id": oid(role_id)})
    return to_public(role)


@app.delete("/roles/{role_id}")
def delete_role(role_id: str, _: dict = Depends(require_permission("manage_roles"))):
    db["role"].delete_one({"_id": oid(role_id)})
    return {"ok": True}


# Posts endpoints
@app.get("/posts")
def list_posts(user: dict = Depends(get_current_user)):
    docs = db["post"].find({}).sort("created_at", -1)
    return [to_public(d) for d in docs]


@app.post("/posts")
def create_post(payload: PostCreate, user: dict = Depends(require_permission("create"))):
    schema = PostSchema(title=payload.title, content=payload.content, status=payload.status, author_id=str(user["_id"]))
    pid = create_document("post", schema)
    post = db["post"].find_one({"_id": oid(pid)})
    return to_public(post)


@app.patch("/posts/{post_id}")
def update_post(post_id: str, payload: PostUpdate, user: dict = Depends(require_permission("edit"))):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    update["updated_at"] = datetime.now(timezone.utc)
    db["post"].update_one({"_id": oid(post_id)}, {"$set": update})
    post = db["post"].find_one({"_id": oid(post_id)})
    return to_public(post)


@app.delete("/posts/{post_id}")
def delete_post(post_id: str, user: dict = Depends(require_permission("delete"))):
    db["post"].delete_one({"_id": oid(post_id)})
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
