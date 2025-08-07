from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

from schemas.accounts import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema, PasswordResetRequestSchema
from security.passwords import hash_password

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = result.scalars().first()
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")

    try:
        hashed = hash_password(user.password)
        new_user = UserModel(email=user.email, password=hashed, group_id=user.role)
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        access_token = ActivationTokenModel(user=new_user)
        db.add(access_token)
        await db.commit()
        await db.refresh(access_token)

        return new_user

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user_account(request: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.token == request.token)
    )
    activation_token = result.scalars().first()

    if not activation_token or activation_token.expires_at < datetime.now():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == request.email)
    )
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def reset_password(request: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == request.email))
    db_user = result.scalars().first()
    if db_user and db_user.is_active:

        new_token = PasswordResetTokenModel(user=db_user)
        db.add(new_token)
        await db.commit()
        await db.refresh(new_token)

    return {"message": "If you are registered, you will receive an email with instructions."}
