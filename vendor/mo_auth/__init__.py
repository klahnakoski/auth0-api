from flask import _request_ctx_stack, request, session, Response
from jose import jwt

from mo_auth import flask_session
from mo_dots import wrap
from mo_future import decorate, first
from mo_json import value2json
from mo_times import Date
from pyLibrary.env import http
from vendor.mo_logs import Log

DEBUG = False


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


class Authenticator(object):
    def __init__(self, auth0, permissions, session_manager):
        if not auth0.domain:
            Log.error("expecting auth0 configuration")
        self.auth0 = auth0
        self.permissions = permissions
        self.session_manager = session_manager

    def requires_auth(self):
        """
        USE THIS TO MARKUP ENDPOINTS WITH AUTHENTICATION
        """

        def output(f):
            @decorate(f)
            def verify(*args, **kwargs):
                self.authorize_user()
                return f(*args, **kwargs)

            return verify

        return output

    def markup_user(self):
        # WHAT IS THE EMPLOY STATUS OF THE USER?
        pass

    def verify_opaque_token(self, token):
        # Opaque Access Token
        url = "https://" + self.auth0.domain + "/userinfo"
        response = http.get_json(url, headers={"Authorization": "Bearer " + token})
        DEBUG and Log.note("content: {{body|json}}", body=response)
        return response

    def verify_jwt_token(self, token):
        jwks = http.get_json("https://" + self.auth0.domain + "/.well-known/jwks.json")
        unverified_header = jwt.get_unverified_header(token)
        algorithm = unverified_header["alg"]
        if algorithm != "RS256":
            Log.error("Expecting a RS256 signed JWT Access Token")

        key_id = unverified_header["kid"]
        key = first(key for key in jwks["keys"] if key["kid"] == key_id)
        if not key:
            Log.error("could not find {{key}}", key=key_id)

        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=algorithm,
                audience=self.auth0.api.identifier,
                issuer="https://" + self.auth0.domain + "/",
            )
            _request_ctx_stack.top.current_user = payload
        except jwt.ExpiredSignatureError as e:
            Log.error("Token has expired", code=403, cause=e)
        except jwt.JWTClaimsError as e:
            Log.error(
                "Incorrect claims, please check the audience and issuer",
                code=403,
                cause=e,
            )
        except Exception as e:
            Log.error("Problem parsing", cause=e)

    def authorize(self):
        """
        EXPECT AN ACCESS TOKEN, RETURN A SESSION TOKEN
        """
        now = Date.now().unix
        try:
            access_token = get_token_auth_header()
            user_details = self.verify_opaque_token(access_token)

            # ADD TO SESSION
            self.session_manager.setup_session(session)
            session.user = self.permissions.get_or_create_user(user_details)
            session.last_used = now

            self.markup_user()

            return Response(value2json(self.session_manager.make_cookie(session)), status=200)
        except Exception as e:
            session["user"] = None
            session["last_used"] = None
            Log.error("failure to authorize", cause=e)


def verify_user(func):
    """
    VERIFY A user EXISTS IN THE SESSION, PASS IT TO func
    """
    @decorate(func)
    def output(*args, **kwargs):
        # IS THIS A NEW SESSION
        now = Date.now().unix
        user = session.get("user")
        if not user:
            Log.error("must authorize first")

        session["last_used"] = now
        return func(*args, user=user, **kwargs)

    return output