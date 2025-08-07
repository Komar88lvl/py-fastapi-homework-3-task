from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=30)


class UserRegistrationResponseSchema(BaseModel):
    pass


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
