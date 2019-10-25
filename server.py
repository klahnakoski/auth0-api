from flask import Flask, jsonify, Response

from mo_auth import Authenticator, requires_scope
from mo_auth.permissions import Permissions
from mo_dots import coalesce
from mo_json import value2json
from mo_logs import startup, constants, Except
from mo_threads.threads import register_thread
from pyLibrary.env.flask_session import setup_flask_session
from pyLibrary.env.flask_wrappers import cors_wrapper, setup_flask_ssl
from pyLibrary.sql.sqlite import Sqlite
from vendor.mo_logs import Log

DEBUG = True
APP = Flask(__name__)


@APP.errorhandler(Exception)
@register_thread
def handle_auth_error(ex):
    ex = Except.wrap(ex)
    code = coalesce(ex.params.code, 401)
    Log.warning("sending error to client\n{{error}}", {"error": ex})
    return Response(value2json(ex), status=code)


@APP.route("/", defaults={"path": ""}, methods=["OPTIONS", "HEAD"])
@APP.route("/<path:path>", methods=["OPTIONS", "HEAD"])
@cors_wrapper
def nothing(*args, **kwargs):
    return Response("", status=200)


# Controllers API
@APP.route("/api/public")
@register_thread
@cors_wrapper
def public():
    """No access token required to access this route
    """
    response = (
        "Hello from a public endpoint! You don't need to be authenticated to see this."
    )
    return jsonify(message=response)


config = startup.read_settings()
constants.set(config.constants)
Log.start(config.debug)

perm = Permissions(Sqlite(config.permissions.store))
auth = Authenticator(config.auth0, perm)


@APP.route("/api/private", methods=["GET", "POST"])
@register_thread
@cors_wrapper
@auth.requires_auth()
def private():
    """A valid access token is required to access this route
    """
    response = (
        "Hello from a private endpoint! You need to be authenticated to see this."
    )
    return jsonify(message=response)


@APP.route("/api/private-scoped")
@register_thread
@cors_wrapper
@auth.requires_auth()
def private_scoped():
    """A valid access token and an appropriate scope are required to access this route
    """
    if requires_scope(config.auth0.scope):
        response = "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this."
        return jsonify(message=response)
    Log.error("You don't have access to {{scope}}", scope=config.auth0.scope, code=403)


Log.note("start servers")
setup_flask_ssl(APP, config.flask)
setup_flask_session(APP, config.session)
APP.run(**config.flask)
