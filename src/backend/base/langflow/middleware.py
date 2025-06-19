import httpx
import os
from fastapi import FastAPI, Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from jose import jwt, jwk
from jose.exceptions import JOSEError
from typing import Optional
from loguru import logger

from langflow.services.deps import get_settings_service

# Middleware for handling organization-specific database connections and JWT validation
CLERK_FRONTEND_API_URL = os.environ.get("CLERK_FRONTEND_API_URL", "https://your-clerk-domain.com") # Replace with your actual Clerk Frontend API URL or set ENV
CLERK_JWT_AUDIENCE = os.environ.get("CLERK_JWT_AUDIENCE", None) # Replace/set if audience validation is needed
CLERK_ALGORITHM = "RS256" # Algorithm for JWKS

class MaxFileSizeException(HTTPException):
    def __init__(self, detail: str = "File size is larger than the maximum file size {}MB"):
        super().__init__(status_code=413, detail=detail)

class OrgDatabaseMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.jwks = None
        self.jwks_uri = self._get_jwks_uri()
        if self.jwks_uri:
            self._load_jwks()

    def _get_jwks_uri(self) -> Optional[str]:
        if not CLERK_FRONTEND_API_URL:
            logger.error("CLERK_FRONTEND_API_URL is not configured.")
            return None
        # Ensure the URL ends with a slash before appending
        base_url = CLERK_FRONTEND_API_URL
        if not base_url.endswith('/'):
            base_url += '/'
        return f"{base_url}.well-known/jwks.json"

    def _load_jwks(self):
        logger.info(f"Attempting to load JWKS from {self.jwks_uri}")
        try:
            with httpx.Client() as client:
                response = client.get(self.jwks_uri)
                response.raise_for_status()  # Raises HTTPStatusError for 4xx/5xx responses
                self.jwks = response.json()
                logger.info("JWKS loaded successfully.")
        except httpx.RequestError as e:
            logger.error(f"Error fetching JWKS from {self.jwks_uri}: {e}")
            self.jwks = None # Ensure jwks is None if fetching fails
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error {e.response.status_code} fetching JWKS from {self.jwks_uri}: {e.response.text}")
            self.jwks = None
        except Exception as e:
            logger.error(f"An unexpected error occurred while loading JWKS: {e}")
            self.jwks = None

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ):
        token = None
        # Attempt to extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            logger.debug("Token found in Authorization header.")

        # If not in header, try to get from cookie
        if not token:
            token = request.cookies.get("__session")
            if token:
                logger.debug("Token found in __session cookie.")

        if token:
            if not self.jwks:
                logger.warning("JWKS not loaded, cannot validate token. Proceeding without org_id.")
            else:
                try:
                    logger.debug("Attempting to decode token.")
                    # PyJWT and python-jose might have different key formats for JWKS.
                    # python-jose's jwt.decode typically expects the key directly or a dict for JWKS.
                    # For JWKS, python-jose usually handles key selection internally if given the full JWKS.
                    # However, often one needs to find the correct key from JWKS based on token's kid.
                    
                    # First, get the unverified header to find the Key ID (kid)
                    unverified_header = jwt.get_unverified_header(token)
                    kid = unverified_header.get("kid")

                    if not kid:
                        logger.warning("Token header does not contain 'kid'. Cannot select key from JWKS.")
                    else:
                        # Find the key in JWKS that matches the kid
                        rsa_key = {}
                        for key_dict in self.jwks["keys"]:
                            if key_dict["kid"] == kid:
                                rsa_key = {
                                    "kty": key_dict["kty"],
                                    "kid": key_dict["kid"],
                                    "use": key_dict["use"],
                                    "n": key_dict["n"],
                                    "e": key_dict["e"]
                                }
                                # For RS256, 'alg' might also be in the key or you might need to ensure it matches
                                if 'alg' in key_dict:
                                     rsa_key['alg'] = key_dict['alg']
                                break
                        
                        if not rsa_key:
                            logger.warning(f"No matching key found in JWKS for kid: {kid}")
                        else:
                            decoded_token = jwt.decode(
                                token,
                                rsa_key, # Pass the specific key, not the whole JWKS
                                algorithms=[CLERK_ALGORITHM],
                                audience=CLERK_JWT_AUDIENCE,
                            )
                            org_id = decoded_token.get("org_id")
                            if org_id:
                                request.state.org_id = org_id
                                logger.info(f"Organization ID {org_id} found in token and set in request.state.")
                            else:
                                logger.info("org_id not found in token claims after successful decoding.")
                
                except jwt.ExpiredSignatureError:
                    logger.warning("Token has expired.")
                except jwt.JWTClaimsError as e:
                    logger.warning(f"JWT claims error: {e}")
                except JOSEError as e: # Broad category for jose specific errors
                    logger.warning(f"Error decoding token: {e}")
                except Exception as e:
                    logger.error(f"An unexpected error occurred during token processing: {e}")
        else:
            logger.debug("No token found in Authorization header or __session cookie.")

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