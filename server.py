from functools import wraps
from ssl import PROTOCOL_SSLv23, SSLContext

from flask import Flask, request, jsonify, _request_ctx_stack, Response
from jose import jwt

from mo_dots import is_data, wrap, coalesce
from mo_files import TempFile, File
from mo_json import value2json
from mo_logs import startup, constants, Except
from mo_threads import Thread
from mo_threads.threads import register_thread
from pyLibrary.env import http
from pyLibrary.env.flask_wrappers import cors_wrapper
from vendor.mo_logs import Log

DEBUG = True
ALGORITHMS = ["RS256"]
APP = Flask(__name__)


@APP.errorhandler(Exception)
@register_thread
def handle_auth_error(ex):
    ex = Except.wrap(ex)
    code = coalesce(ex.params.code, 401)
    Log.warning("sending error to client\n{{error}}", {"error": ex})
    return Response(value2json(ex), status=code)


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


def requires_auth(f):
    """Determines if the access token is valid"""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        DEBUG and Log.note("verify {{token|limit(40)}}", token=token)
        if len(token.split('.')) != 3:
            # Opaque Access Token
            url = "https://" + AUTH0_DOMAIN + "/userinfo"
            response = http.get_json(url, headers={"Authorization": 'Bearer ' + token})
            DEBUG and Log.note("content: {{body|json}}", body=response)
            return f(*args, **kwargs)

        jwks = http.get_json("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
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
                        audience=API_IDENTIFIER,
                        issuer="https://" + AUTH0_DOMAIN + "/"
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


@APP.route('/', defaults={'path': ''}, methods=['OPTIONS', 'HEAD'])
@APP.route('/<path:path>', methods=['OPTIONS', 'HEAD'])
@cors_wrapper
def nothing(*args, **kwargs):
    return Response(
        "",
        status=200
    )


# Controllers API
@APP.route("/api/public")
@register_thread
@cors_wrapper
def public():
    """No access token required to access this route
    """
    response = "Hello from a public endpoint! You don't need to be authenticated to see this."
    return jsonify(message=response)


@APP.route("/api/private", methods=['GET', 'POST'])
@register_thread
@cors_wrapper
@requires_auth
def private():
    """A valid access token is required to access this route
    """
    response = "Hello from a private endpoint! You need to be authenticated to see this."
    return jsonify(message=response)


@APP.route("/api/private-scoped")
@register_thread
@cors_wrapper
@requires_auth
def private_scoped():
    """A valid access token and an appropriate scope are required to access this route
    """
    if requires_scope(config.auth0.scope):
        response = "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this."
        return jsonify(message=response)
    Log.error("You don't have access to {{scope}}", scope=config.auth0.scope, code=403)


config = None


def setup_flask_ssl():
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
        Log.warning("ActiveData has SSL context, but is still listening on non-encrypted http port {{port}}",
                    port=config.flask.port)

    config.flask.ssl_context = None


if __name__ == "__main__":
    config = startup.read_settings()

    AUTH0_DOMAIN = config.auth0.domain
    API_IDENTIFIER = config.auth0.api.identifier

    constants.set(config.constants)
    Log.start(config.debug)
    Log.note("start servers")
    setup_flask_ssl()
    APP.run(**config.flask)
