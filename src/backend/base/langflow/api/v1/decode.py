import os
import httpx
from fastapi import APIRouter, Request, HTTPException
from jose import jwt, jwk
from jose.exceptions import JOSEError
from typing import Optional, Dict
from loguru import logger
import psycopg2 # For connecting to PostgreSQL
from jose.utils import base64url_decode
from psycopg2 import sql
import psycopg2.extensions

# Constants
JWKS_URL = "https://valued-phoenix-52.clerk.accounts.dev/.well-known/jwks.json"  # Direct JWKS URL
CLERK_ALGORITHM = "RS256"

router = APIRouter(tags=["Decode"])

# Global variable to cache JWKS
_jwks_cache: Optional[Dict] = None

async def get_jwks():
    """
    Fetches JWKS from a hardcoded Clerk URL, caching them for future use.
    """
    global _jwks_cache
    if _jwks_cache:
        return _jwks_cache

    logger.info(f"Attempting to load JWKS from {JWKS_URL}")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(JWKS_URL)
            response.raise_for_status()
            _jwks_cache = response.json()
            logger.info("JWKS loaded and cached successfully.")
            return _jwks_cache
    except httpx.RequestError as e:
        logger.error(f"Error fetching JWKS from {JWKS_URL}: {e}")
        _jwks_cache = None
        raise HTTPException(status_code=503, detail=f"Error fetching JWKS: {e}")
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error {e.response.status_code} fetching JWKS: {e.response.text}")
        _jwks_cache = None
        raise HTTPException(status_code=e.response.status_code, detail=f"HTTP error fetching JWKS: {e.response.text}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading JWKS: {e}")
        _jwks_cache = None
        raise HTTPException(status_code=500, detail=f"Unexpected error loading JWKS: {e}")

def create_database(dbname: str):
    """
    Creates a new PostgreSQL database with the given name.
    """
    logger.info(f"Creating database {dbname}...")
    conn = psycopg2.connect("dbname=langflow user=langflow password=langflow host=localhost port=5432")
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()

    cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))

    cur.close()
    conn.close()
    logger.info(f"Database {dbname} created successfully.")


def initialize_schema(dbname: str):
    """
    Initializes the schema for the given database.
    """
    logger.info(f"Initializing schema for {dbname}...")
    conn = psycopg2.connect(f"dbname={dbname} user=langflow password=langflow host=localhost port=5432")
    cur = conn.cursor()

    # Example schema setup
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    conn.commit()
    cur.close()
    conn.close()
    logger.info(f"Schema initialized for {dbname}.")


@router.post("/decode_token_and_connect", status_code=200)
async def decode_token_and_connect(request: Request):
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(' ')[1]
        logger.info("Token found in Authorization header.")
    elif not token:
        token = request.cookies.get("__session")    

    try:
        # Step 1: Decode JWT header (not verified)
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(status_code=400, detail="No 'kid' found in token header.")

        # Step 2: Get JWKS and find matching key
        jwks = await get_jwks()
        key_data = next((key for key in jwks["keys"] if key["kid"] == kid), None)
        if not key_data:
            raise HTTPException(status_code=401, detail="No matching key found in JWKS.")

        # Step 3: Construct public key
        public_key = jwk.construct(key_data, algorithm=CLERK_ALGORITHM)

        # Step 4: Verify token
        message, encoded_signature = token.rsplit(".", 1)
        decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))

        if not public_key.verify(message.encode("utf-8"), decoded_signature):
            raise HTTPException(status_code=401, detail="Invalid token signature.")

        # Step 5: Now decode and trust claims
        decoded_token = jwt.decode(
            token,
            key=public_key.to_pem().decode("utf-8"),
            algorithms=[CLERK_ALGORITHM],
            options={
                    "verify_signature": False,
                    "verify_exp": False
                }
        )
        logger.info(f"Token decoded successfully.{decoded_token}")

        org_id = decoded_token.get("org_id")
        logger.info(f"org_id: {org_id}")
        if not org_id:
            raise HTTPException(status_code=400, detail="org_id not found in token.")

        logger.info(f"Organization ID {org_id} found in token.")

         # Step 5: Conditionally create DB and initialize schema
        db_name = f"langflow_{org_id}"

        base_conn = psycopg2.connect("dbname=langflow user=langflow password=langflow host=localhost port=5432")
        base_conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        base_cur = base_conn.cursor()

        base_cur.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (db_name,))
        db_exists = base_cur.fetchone()

        base_cur.close()
        base_conn.close()

        if not db_exists:
            logger.info(f"Database {db_name} not found. Creating and initializing...")
            create_database(db_name)
            initialize_schema(db_name)
        else:
            logger.info(f"Database {db_name} already exists. Skipping creation and initialization.")

        # Step 6: Attempt to connect to the org-specific DB
        conn = psycopg2.connect(f"postgresql://langflow:langflow@localhost:5432/{db_name}")
        conn.close()

        logger.info(f"Successfully connected to the database {db_name} for organization {org_id}.")

        return {
            "message": f"Successfully verified token, extracted org_id: {org_id}, and connected to DB: {db_name}."
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except JOSEError as e:
        raise HTTPException(status_code=401, detail=f"Token error: {e}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error.")