from flask import _request_ctx_stack, request
from jose import jwt

from mo_dots import wrap
from mo_future import decorate
from pyLibrary.env import http
from vendor.mo_logs import Log

ALGORITHMS = ["RS256"]

DEBUG = True


def get_token_auth_header():
    """Obtains the access token from the Authorization Header
    """
    try:
        auth = request.headers.get("Authorization", None)
        bearer, token = auth.split()
        if bearer.lower() == "bearer":
            return token
    except Exception as e:
        pass
    Log.error('Expecting "Authorization = Bearer <token>" in header')


def requires_scope(required_scope):
    """Determines if the required scope is present in the access token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    claims = wrap(jwt.get_unverified_claims(token))
    return required_scope in claims.scope.split()


def requires_auth(auth0):
    """Determines if the access token is valid"""
    if not auth0.domain:
        Log.error("expecting auth0 configuration")

    def output(f):
        @decorate(f)
        def decorated(*args, **kwargs):
            token = get_token_auth_header()
            DEBUG and Log.note("verify {{token|limit(40)}}", token=token)
            if len(token.split('.')) != 3:
                # Opaque Access Token
                url = "https://" + auth0.domain + "/userinfo"
                response = http.get_json(url, headers={"Authorization": 'Bearer ' + token})
                DEBUG and Log.note("content: {{body|json}}", body=response)
                return f(*args, **kwargs)

            jwks = http.get_json("https://" + auth0.domain + "/.well-known/jwks.json")
            try:
                unverified_header = jwt.get_unverified_header(token)
            except jwt.JWTError as e:
                Log.error("Expecting a RS256 signed JWT Access Token", cause=e)

            if unverified_header["alg"] == "HS256":
                Log.error("Expecting a RS256 signed JWT Access Token")

            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    try:
                        payload = jwt.decode(
                            token,
                            key,
                            algorithms=ALGORITHMS,
                            audience=auth0.api.identifier,
                            issuer="https://" + auth0.domain + "/"
                        )
                        _request_ctx_stack.top.current_user = payload
                        return f(*args, **kwargs)
                    except jwt.ExpiredSignatureError as e:
                        Log.error("Token has expired", code=403, cause=e)
                    except jwt.JWTClaimsError as e:
                        Log.error("Incorrect claims, please check the audience and issuer", code=403, cause=e)
                    except Exception as e:
                        Log.error("Problem parsing", cause=e)

            Log.error("Unable to find appropriate key")

        return decorated

    return output
