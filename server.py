from flask import Flask, jsonify, Response

from mo_auth.auth0 import Authenticator, requires_scope, verify_user
from mo_auth.flask_session import setup_flask_session
from mo_auth.permissions import Permissions
from mo_dots import coalesce
from mo_json import value2json
from mo_logs import startup, constants, Except
from mo_logs.strings import expand_template
from mo_threads.threads import register_thread
from pyLibrary.env.flask_wrappers import cors_wrapper, setup_flask_ssl, add_flask_rule
from pyLibrary.sql.sqlite import Sqlite
from vendor.mo_logs import Log

DEBUG = True
APP = Flask(__name__)


@APP.errorhandler(Exception)
@register_thread
@cors_wrapper
def handle_auth_error(ex):
    ex = Except.wrap(ex)
    code = coalesce(ex.params.code, 401)
    Log.warning("sending error to client\n{{error}}", {"error": ex})
    return Response(value2json(ex), status=code)


@register_thread
@cors_wrapper
def public():
    """No access token required to access this route
    """
    response = (
        "Hello from a public endpoint! You don't need to be authenticated to see this."
    )
    return jsonify(message=response)


@register_thread
@cors_wrapper
@verify_user
def private(user):
    """A valid access token is required to access this route
    """
    response = expand_template(
        "Hello {{user}} from a private endpoint! You need to be authenticated to see this.",
        {"user": user},
    )
    return jsonify(message=response)


@register_thread
@cors_wrapper
@verify_user
def private_scoped(user):
    """A valid access token and an appropriate scope are required to access this route
    """
    if requires_scope(config.auth0.scope):
        response = (
            "Hello from a private endpoint! You need to be authenticated and have a scope of "
            + config.auth0.scope
            + " to see this."
        )
        return jsonify(message=response)
    Log.error("You don't have access to {{scope}}", scope=config.auth0.scope, code=403)


add_flask_rule(APP, "/api/public", public)
add_flask_rule(APP, "/api/private", private)
add_flask_rule(APP, "/api/private-scoped", private_scoped)


config = startup.read_settings()
constants.set(config.constants)
Log.start(config.debug)

session_manager = setup_flask_session(APP, config.session)
perm = Permissions(Sqlite(config.permissions.store))
auth = Authenticator(APP, config.auth0, perm, session_manager)

Log.note("start servers")
setup_flask_ssl(APP, config.flask)
APP.run(**config.flask)
