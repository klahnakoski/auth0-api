"""Python Flask API Auth0 integration example
"""

import json
from functools import wraps
from os import environ as env
from ssl import PROTOCOL_SSLv23, SSLContext

from dotenv import load_dotenv, find_dotenv
from flask import Flask, request, jsonify, _request_ctx_stack, Response
from jose import jwt
from mo_dots import is_data
from mo_files import TempFile, File
from mo_logs import startup, constants
from mo_threads import Thread
from pyLibrary.env.flask_wrappers import cors_wrapper
from six.moves.urllib.request import urlopen

from vendor.mo_logs import Log

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
API_IDENTIFIER = env.get("API_IDENTIFIER")
ALGORITHMS = ["RS256"]
APP = Flask(__name__)


# Format error response and append status code.
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@APP.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def get_token_auth_header():
    """Obtains the access token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                        "description":
                            "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must start with"
                            " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)

    token = parts[1]
    return token


def requires_scope(required_scope):
    """Determines if the required scope is present in the access token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False


def requires_auth(f):
    """Determines if the access token is valid
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        if unverified_header["alg"] == "HS256":
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_IDENTIFIER,
                    issuer="https://"+AUTH0_DOMAIN+"/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    " please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401)

            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                        "description": "Unable to find appropriate key"}, 401)
    return decorated


@APP.route("/api/private", methods=['OPTIONS', 'HEAD'])
@cors_wrapper
def nothing():
    return Response(
        "",
        status=200
    )

# Controllers API
@APP.route("/api/public")
@cors_wrapper
def public():
    """No access token required to access this route
    """
    response = "Hello from a public endpoint! You don't need to be authenticated to see this."
    return jsonify(message=response)


@APP.route("/api/private", methods=['GET', 'POST'])
@cors_wrapper
@requires_auth
def private():
    """A valid access token is required to access this route
    """
    response = "Hello from a private endpoint! You need to be authenticated to see this."
    return jsonify(message=response)


@APP.route("/api/private-scoped")
@cors_wrapper
@requires_auth
def private_scoped():
    """A valid access token and an appropriate scope are required to access this route
    """
    if requires_scope("read:messages"):
        response = "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this."
        return jsonify(message=response)
    raise AuthError({
        "code": "Unauthorized",
        "description": "You don't have access to this resource"
    }, 403)


config = None


def setup_flask_ssl():
    config.flask.ssl_context = None

    if not config.flask.ssl_context:
        return

    ssl_flask = config.flask.copy()
    ssl_flask.debug = False
    ssl_flask.port = 443

    if is_data(config.flask.ssl_context):
        # EXPECTED PEM ENCODED FILE NAMES
        # `load_cert_chain` REQUIRES CONCATENATED LIST OF CERTS
        with TempFile() as tempfile:
            try:
                tempfile.write(File(ssl_flask.ssl_context.certificate_file).read_bytes())
                if ssl_flask.ssl_context.certificate_chain_file:
                    tempfile.write(File(ssl_flask.ssl_context.certificate_chain_file).read_bytes())
                tempfile.flush()
                tempfile.close()

                context = SSLContext(PROTOCOL_SSLv23)
                context.load_cert_chain(tempfile.name, keyfile=File(ssl_flask.ssl_context.privatekey_file).abspath)

                ssl_flask.ssl_context = context
            except Exception as e:
                Log.error("Could not handle ssl context construction", cause=e)

    def runner(please_stop):
        Log.warning("ActiveData listening on encrypted port {{port}}", port=ssl_flask.port)
        APP.run(**ssl_flask)

    Thread.run("SSL Server", runner)

    if config.flask.ssl_context and config.flask.port != 80:
        Log.warning("ActiveData has SSL context, but is still listening on non-encrypted http port {{port}}", port=config.flask.port)

    config.flask.ssl_context = None


if __name__ == "__main__":
    config = startup.read_settings()

    constants.set(config.constants)
    Log.start(config.debug)
    setup_flask_ssl()
    APP.run(host="0.0.0.0", port=env.get("PORT", 5000))
