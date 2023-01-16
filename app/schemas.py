from datetime import datetime
from pydantic import BaseModel, EmailStr, constr


class UserBaseSchema(BaseModel):
    username: str
    email: EmailStr
    photo: str
    role: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        orm_mode = True


class CreateUserSchema(UserBaseSchema):
    password: constr(min_length=8)
    passwordConfirm: str
    verified: bool = False


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8)


class UserResponseSchema(UserBaseSchema):
    id: str
    pass


class UserResponse(BaseModel):
    status: str
    user: UserResponseSchema
    
class ResetPasswordRequestSchema(BaseModel):
    email: EmailStr

class ResetPasswordSchema(BaseModel):
    password: constr(min_length=8)
    passwordConfirm: constr(min_length=8)

class ChangePasswordSchema(BaseModel):
    currentPassword: constr(min_length=8)
    newPassword: constr(min_length=8)
    passwordConfirm: constr(min_length=8)