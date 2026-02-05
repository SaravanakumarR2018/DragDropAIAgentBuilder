"""Constants for Clerk JWT and Paddle metadata keys.

This module centralizes all metadata key definitions to ensure consistency
across Clerk JWT payload extraction and Paddle customer data storage.
"""

# ============================================================================
# Clerk JWT Payload Keys
# ============================================================================

# Standard Clerk claims
CLERK_JWT_SUB_KEY = "sub"  # Clerk user ID (unique identifier)
CLERK_JWT_EMAIL_KEY = "email"  # User email address
CLERK_JWT_ORG_KEY = "o"  # Organization object

# Custom claims added by verify_clerk_token
CLERK_JWT_UUID_KEY = "uuid"  # Deterministic UUID derived from Clerk ID

# ============================================================================
# Public Metadata Keys (stored in Clerk public_metadata and JWT)
# ============================================================================

PADDLE_CUSTOMER_ID_KEY = "paddle_customer_id"  # Paddle customer ID

# ============================================================================
# Custom Data Keys (stored in Paddle customer custom_data)
# ============================================================================

PADDLE_CUSTOM_DATA_ORG_ID_KEY = "org_id"  # Organization ID
PADDLE_CUSTOM_DATA_USER_ID_KEY = "user_id"  # Clerk user ID

# ============================================================================
# Organization Metadata
# ============================================================================

ORG_ID_KEY = "org_id"  # Organization ID key (used in multiple contexts)
