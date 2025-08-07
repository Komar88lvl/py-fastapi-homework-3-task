from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=30)


    @field_validator("password")
    @classmethod
    def password_strength_validator(cls, password: str) -> str:
        return accounts_validators.validate_password_strength(password)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


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
