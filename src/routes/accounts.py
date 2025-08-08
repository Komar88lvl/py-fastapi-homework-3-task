from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
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

from schemas.accounts import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema
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

    except SQLAlchemyError:
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


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(request: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    token_result = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.token == request.token))

    token = token_result.scalars().first()

    user_result = await db.execute(select(UserModel).where(UserModel.email == request.email))
    db_user = user_result.scalars().first()

    if (not token
        or not db_user
        or not db_user.is_active
        or db_user.email != request.email
    ):
        if db_user:
            token_by_user = await db.execute(
                select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
            )
            token_to_delete = token_by_user.scalars().first()
            if token_to_delete:
                await db.delete(token_to_delete)
                await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if token.expires_at < datetime.now():
        await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        db_user.password = request.password
        await db.delete(token)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    request: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    user_result = await db.execute(select(UserModel).where(UserModel.email == request.email))
    db_user = user_result.scalars().first()

    if not db_user or not db_user.verify_password(request.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        token_data = {"user_id": db_user.id, "email": db_user.email}

        access_token = jwt_manager.create_access_token(data=token_data)
        refresh_token = jwt_manager.create_refresh_token(data=token_data)

        refresh_token_obj = RefreshTokenModel(token=refresh_token, user_id=db_user.id)
        db.add(refresh_token_obj)

        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token
        )


    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
