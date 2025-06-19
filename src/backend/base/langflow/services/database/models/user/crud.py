from datetime import datetime, timezone
from typing import Optional # Added Optional
from uuid import UUID, uuid4 # Added uuid4

from fastapi import HTTPException, status
from loguru import logger
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.attributes import flag_modified
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

# Assuming SettingsService will be passed as an argument, not imported globally here
# from langflow.services.settings.service import SettingsService
from langflow.services.database.models.user.model import User, UserCreate, UserUpdate # Added UserCreate
from langflow.services.auth.utils import get_password_hash # For native user creation if ever consolidated


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    stmt = select(User).where(User.username == username)
    return (await db.exec(stmt)).first()


async def get_user_by_id(db: AsyncSession, user_id: UUID) -> User | None:
    if isinstance(user_id, str):
        user_id = UUID(user_id)
    stmt = select(User).where(User.id == user_id)
    return (await db.exec(stmt)).first()


async def update_user(user_db: User | None, user: UserUpdate, db: AsyncSession) -> User:
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")

    # user_db_by_username = get_user_by_username(db, user.username)
    # if user_db_by_username and user_db_by_username.id != user_id:
    #     raise HTTPException(status_code=409, detail="Username already exists")

    user_data = user.model_dump(exclude_unset=True)
    changed = False
    for attr, value in user_data.items():
        if hasattr(user_db, attr) and value is not None:
            setattr(user_db, attr, value)
            changed = True

    if not changed:
        raise HTTPException(status_code=status.HTTP_304_NOT_MODIFIED, detail="Nothing to update")

    user_db.updated_at = datetime.now(timezone.utc)
    flag_modified(user_db, "updated_at")

    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=str(e)) from e

    return user_db


async def update_user_last_login_at(user_id: UUID, db: AsyncSession):
    try:
        user_data = UserUpdate(last_login_at=datetime.now(timezone.utc))
        user = await get_user_by_id(db, user_id)
        return await update_user(user, user_data, db)
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error updating user last login at: {e!s}")


async def get_user_by_clerk_id(db_session: AsyncSession, clerk_id: str) -> Optional[User]:
    """Retrieves a user by their Clerk user ID."""
    return (await db_session.exec(select(User).where(User.clerk_user_id == clerk_id))).first()


async def create_user_from_clerk(db_session: AsyncSession, user_data: dict) -> User:
    """
    Creates a new user in Langflow from Clerk user data.
    Sets a non-usable password as Clerk manages authentication.
    """
    clerk_user_id = user_data.get("clerk_user_id")
    if not clerk_user_id:
        raise ValueError("clerk_user_id is required to create a user from Clerk data.")

    # Ensure username is unique, potentially suffixing with part of clerk_id if conflicts occur
    # For now, assume username provided from Clerk (or derived from email/sub) is acceptable
    # or that calling function handles potential uniqueness issues before this point.
    username = user_data.get("username")
    if not username:
        # Fallback to clerk_user_id if username is not provided
        # This is a safe bet for uniqueness if email is not used or not unique
        username = clerk_user_id

    # Check if username already exists
    existing_user_by_username = await get_user_by_username(db_session, username)
    if existing_user_by_username:
        # Handle username conflict, e.g. by appending a short hash of clerk_id or raising an error
        # For this example, let's raise an error or modify the username
        # This logic might need refinement based on product decisions
        logger.warning(f"Username {username} already exists. Modifying for Clerk user {clerk_user_id}.")
        username = f"{username}_{clerk_user_id[:8]}" # Example modification

    db_user = User(
        clerk_user_id=clerk_user_id,
        username=username,
        email=user_data.get("email"), # Assuming User model has an 'email' field
        password=None, # Password is not set as Clerk handles authentication
        is_active=user_data.get("is_active", True),
        is_superuser=user_data.get("is_superuser", False),
        profile_image=user_data.get("profile_image_url"),
        create_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    try:
        db_session.add(db_user)
        await db_session.commit()
        await db_session.refresh(db_user)
        return db_user
    except IntegrityError as e:
        await db_session.rollback()
        # This might happen if, despite checks, username or another unique field conflicts
        logger.error(f"Error creating user from Clerk: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not create user. Integrity error: {e.orig}",
        )
    except Exception as e:
        await db_session.rollback()
        logger.error(f"Unexpected error creating user from Clerk: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while creating the user.",
        )


# Example of how a native user creation function might look (uses get_password_hash)
# This is NOT part of the Clerk changes but for context on password hashing.
async def create_native_user(db_session: AsyncSession, user_create: UserCreate) -> User:
    """Creates a new native user with a hashed password."""
    hashed_password = get_password_hash(user_create.password)
    db_user = User(
        username=user_create.username,
        password=hashed_password,
        is_active=True, # Or based on settings_service.auth_settings.NEW_USER_IS_ACTIVE
        is_superuser=False,
        create_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        optins=user_create.optins
    )
    try:
        db_session.add(db_user)
        await db_session.commit()
        await db_session.refresh(db_user)
        return db_user
    except IntegrityError as e:
        await db_session.rollback()
        logger.error(f"Error creating native user: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{user_create.username}' already exists.",
        )
