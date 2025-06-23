import httpx
import os
from fastapi import FastAPI, Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from jose import jwt, jwk
from jose.exceptions import JOSEError
from typing import Optional
from loguru import logger
from jose.utils import base64url_decode

from langflow.services.deps import get_settings_service

# Middleware for handling organization-specific database connections and JWT validation
# Constants
JWKS_URL = "https://valued-phoenix-52.clerk.accounts.dev/.well-known/jwks.json"  # Direct JWKS URL
CLERK_ALGORITHM = "RS256"

class MaxFileSizeException(HTTPException):
    def __init__(self, detail: str = "File size is larger than the maximum file size {}MB"):
        super().__init__(status_code=413, detail=detail)

class OrgDatabaseMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.jwks = None
        self._load_jwks()

    def _load_jwks(self):
        logger.info(f"Attempting to load JWKS from {JWKS_URL}")
        try:
            with httpx.Client() as client:
                response = client.get(JWKS_URL)
                response.raise_for_status()  # Raises HTTPStatusError for 4xx/5xx responses
                self.jwks = response.json()
                logger.info("JWKS loaded successfully.")
        except httpx.RequestError as e:
            logger.error(f"Error fetching JWKS from {JWKS_URL}: {e}")
            self.jwks = None # Ensure jwks is None if fetching fails
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error {e.response.status_code} fetching JWKS from {JWKS_URL}: {e.response.text}")
            self.jwks = None
        except Exception as e:
            logger.error(f"An unexpected error occurred while loading JWKS: {e}")
            self.jwks = None

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        elif not token:
            token = request.cookies.get("__session")

        if token and self.jwks:
            try:
                headers = jwt.get_unverified_header(token)
                kid = headers.get("kid")
                if not kid:
                    logger.warning("No 'kid' in token header.")
                else:
                    key_data = next((key for key in self.jwks["keys"] if key["kid"] == kid), None)
                    if not key_data:
                        logger.warning("No matching key found in JWKS.")
                    else:
                        public_key = jwk.construct(key_data, algorithm=CLERK_ALGORITHM)
                        message, encoded_signature = token.rsplit(".", 1)
                        decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
                        if not public_key.verify(message.encode("utf-8"), decoded_signature):
                            logger.warning("Invalid token signature.")
                        else:
                            decoded_token = jwt.decode(
                                token,
                                key=public_key.to_pem().decode("utf-8"),
                                algorithms=[CLERK_ALGORITHM],
                                options={
                                    "verify_signature": False,
                                    "verify_exp": False
                                }
                            )
                            logger.info(f"Token decoded successfully: {decoded_token}")
                            org_id = decoded_token.get("org_id")
                            logger.info(f"org_id: {org_id}")
                            if org_id:
                                request.state.org_id = org_id
                                logger.info(f"org_id {org_id} set in request.state.")
            except Exception as e:
                logger.warning(f"JWT/JWKS error: {e}")

        response = await call_next(request)
        return response

# Adapted from https://github.com/steinnes/content-size-limit-asgi/blob/master/content_size_limit_asgi/middleware.py#L26
class ContentSizeLimitMiddleware:
    """Content size limiting middleware for ASGI applications.

    Args:
      app (ASGI application): ASGI application
      max_content_size (optional): the maximum content size allowed in bytes, None for no limit
      exception_cls (optional): the class of exception to raise (ContentSizeExceeded is the default)
    """

    def __init__(
        self,
        app,
    ):
        self.app = app
        self.logger = logger

    @staticmethod
    def receive_wrapper(receive):
        received = 0

        async def inner():
            max_file_size_upload = get_settings_service().settings.max_file_size_upload
            nonlocal received
            message = await receive()
            if message["type"] != "http.request" or max_file_size_upload is None:
                return message
            body_len = len(message.get("body", b""))
            received += body_len
            if received > max_file_size_upload * 1024 * 1024:
                # max_content_size is in bytes, convert to MB
                received_in_mb = round(received / (1024 * 1024), 3)
                msg = (
                    f"Content size limit exceeded. Maximum allowed is {max_file_size_upload}MB"
                    f" and got {received_in_mb}MB."
                )
                raise MaxFileSizeException(msg)
            return message

        return inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        wrapper = self.receive_wrapper(receive)
        await self.app(scope, wrapper, send)