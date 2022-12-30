# schemas.py
import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr, constr


class UserBaseSchema(BaseModel):
    username: str
    full_name: str
    email: EmailStr
    photo: str

    class Config:
        orm_mode = True


class CreateUserSchema(UserBaseSchema):
    password: constr(min_length=8)
    passwordConfirm: str
    role: str = 'user'
    verified: bool = False


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8)


class UserResponse(UserBaseSchema):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class FilteredUserResponse(UserBaseSchema):
    pass


class ResetPasswordRequestSchema(BaseModel):
    email: EmailStr


class ResetPasswordSchema(BaseModel):
    passwordResetCode: str
    password: constr(min_length=8)
    passwordConfirm: constr(min_length=8)


class ChangePasswordSchema(BaseModel):
    currentPassword: constr(min_length=8)
    newPassword: constr(min_length=8)
    passwordConfirm: constr(min_length=8)
