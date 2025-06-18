import asyncio # Added for async sleep in mock
from typing import Dict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select # Added for DB query
from langflow.services.database.models.user.model import User
from langflow.services.utils import get_unique_username # For generating unique username

# Placeholder for python-clerk SDK or JWKS verification logic
# For now, this function will simulate token verification.
# In a real scenario, this would involve checking the token against Clerk's JWKS URI
# or using the python-clerk SDK.
async def verify_clerk_token(token: str, secret_key: str) -> Dict: # Made async
    """
    Verifies a Clerk token.

    Args:
        token: The JWT token from Clerk.
        secret_key: The Clerk secret key.

    Returns:
        A dictionary with token claims if valid, otherwise raises an exception or returns None.
    """
    # This is a mock verification.
    # Replace with actual verification logic using Clerk's SDK or JWKS.
    await asyncio.sleep(0) # Simulate async operation
    if token == "valid_token" and secret_key:
        # Simulate successful verification with mock claims
        # Ensure email_addresses is a list of objects, each with an email_address field
        return {
            "sub": "user_clerk_id_123",  # Simulated Clerk User ID
            "email_addresses": [{"email_address": "test@example.com"}],
            "first_name": "Test",
            "last_name": "User",
            # Add other relevant claims as needed
        }
    elif not secret_key:
        # Raising ValueError to be caught by the caller
        raise ValueError("Clerk secret key is not configured.")
    else:
        # Simulate token verification failure
        # Raising ValueError to be caught by the caller
        raise ValueError("Invalid token")

async def get_or_create_clerk_user(claims: Dict, db: AsyncSession) -> User:
    """
    Retrieves an existing user based on Clerk User ID or creates a new one.

    Args:
        claims: Token claims from Clerk, expected to contain 'sub' and 'email_addresses'.
        db: The database session.

    Returns:
        The User object.
    """
    clerk_id = claims.get("sub")
    if not clerk_id:
        raise ValueError("Clerk User ID ('sub') not found in claims.")

    # Clerk might provide multiple email addresses, use the first one as primary
    # The structure is typically [{"email_address": "user@example.com", ...}, ...]
    email_list = claims.get("email_addresses", [])
    if not email_list or not isinstance(email_list, list) or len(email_list) == 0:
        # Depending on Clerk setup, email might not always be present or might not be primary.
        # For Langflow, we'll assume an email is needed for the username.
        # If not available, a generic username or another claim could be used.
        # For now, raise if no email is found.
        raise ValueError("Email address not found in Clerk claims.")

    # Get the actual email string from the first object in the list
    email = email_list[0].get("email_address")
    if not email:
        raise ValueError("Email address value not found in Clerk claims.")

    # Query for an existing user by clerk_user_id
    result = await db.execute(select(User).where(User.clerk_user_id == clerk_id))
    user = result.scalar_one_or_none()

    if user:
        return user

    # User not found, create a new one
    # Generate a unique username to avoid conflicts if email is already in use by a non-Clerk user
    # Or, if emails are guaranteed to be unique across all users (Clerk or not),
    # then `email` can be used directly if `User.username` has a unique constraint.
    # The User model has `username: str = Field(index=True, unique=True)`.
    # So, we must ensure the username is unique.

    # A simple way to attempt uniqueness for now, or use a helper like get_unique_username
    # For this subtask, let's assume a helper `get_unique_username` or handle potential conflict.
    # If `get_unique_username` is not available, we might need to query to check if username exists.
    # The `get_unique_username` helper is in `langflow.services.utils`.
    unique_username = await get_unique_username(db, email)

    user = User(
        username=unique_username,
        # email=email, # User model does not have a direct email field, username often serves as email.
                      # If User model had an email field, it would be set here.
        clerk_user_id=clerk_id,
        is_active=True,  # Assuming users verified by Clerk are active
        is_superuser=False, # Default for new users
        # Langflow's User model requires a password.
        # For Clerk-authenticated users, this password won't be used for login via Langflow's form.
        # Setting it to a non-usable value or allowing it to be None if the model permits.
        # The User model has `password: str = Field()`. This is an issue.
        # It should be `password: str | None = Field(default=None)` for external auth.
        # Let's check the User model again.
        # User model has `password: str = Field()`. This means it's required.
        # This is a problem for externally authenticated users.
        # For the purpose of this subtask, I will set a placeholder password.
        # This should be revisited: ideally, User.password should be Optional.
        password="clerk_authenticated_user_placeholder_password", # Placeholder
        profile_image=claims.get("picture") or claims.get("profile_image_url"), # if available in claims
        # Other fields like create_at, updated_at have default_factory
    )
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
    except Exception as e:
        await db.rollback()
        # This could happen if unique_username was not unique enough (race condition)
        # or other DB constraints.
        raise ValueError(f"Failed to create new Clerk user: {e}")

    return user
