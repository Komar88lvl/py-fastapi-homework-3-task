from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

from database.models.accounts import UserGroupEnum



class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    role: UserGroupEnum = UserGroupEnum.USER


    @field_validator("password")
    @classmethod
    def password_strength_validator(cls, password: str) -> str:
        return accounts_validators.validate_password_strength(password)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr
    role: UserGroupEnum = UserGroupEnum.USER


class UserActivationRequestSchema(BaseModel):
    pass


class MessageResponseSchema(BaseModel):
    pass


class PasswordResetRequestSchema(BaseModel):
    pass


class PasswordResetCompleteRequestSchema(BaseModel):
    pass


class UserLoginResponseSchema(BaseModel):
    pass


class UserLoginRequestSchema(BaseModel):
    pass


class TokenRefreshRequestSchema(BaseModel):
    pass


class TokenRefreshResponseSchema(BaseModel):
    pass
