from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Literal

# RBAC CMS Schemas
# Each class maps to a MongoDB collection with the lowercase name

class Role(BaseModel):
    name: str = Field(..., description="Role name, e.g., Admin, Editor, Viewer")
    permissions: List[str] = Field(default_factory=list, description="List of permission keys")

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    role_id: Optional[str] = Field(None, description="Reference to role _id as string")
    is_active: bool = Field(True, description="Whether user is active")

class Post(BaseModel):
    title: str = Field(..., description="Post title")
    content: str = Field("", description="Post content")
    status: Literal['Draft', 'Published'] = Field('Draft', description="Publication status")
    author_id: Optional[str] = Field(None, description="Author user _id as string")
