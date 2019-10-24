# encoding: utf-8
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Author: Kyle Lahnakoski (kyle@lahnakoski.com)
#
from __future__ import absolute_import, division, unicode_literals

from functools import update_wrapper
from ssl import PROTOCOL_SSLv23, SSLContext

import flask
from flask import Response
from pyLibrary.sql.sqlite import Sqlite

from mo_dots import coalesce, is_data, missing, wrap, exists
from mo_files import File, TempFile
from mo_future import text_type
from mo_json import value2json
from mo_logs import Log
from mo_logs.strings import unicode2utf8
from mo_threads import Thread
from pyLibrary.env import git
from pyLibrary.env.big_data import ibytes2icompressed

TOO_SMALL_TO_COMPRESS = 510  # DO NOT COMPRESS DATA WITH LESS THAN THIS NUMBER OF BYTES


def gzip_wrapper(func, compress_lower_limit=None):
    compress_lower_limit = coalesce(compress_lower_limit, TOO_SMALL_TO_COMPRESS)

    def output(*args, **kwargs):
        response = func(*args, **kwargs)
        accept_encoding = flask.request.headers.get("Accept-Encoding", "")
        if "gzip" not in accept_encoding.lower():
            return response

        response.headers["Content-Encoding"] = "gzip"
        response.response = ibytes2icompressed(response.response)

        return response

    return output


def cors_wrapper(func):
    """
    Decorator for CORS
    :param func:  Flask method that handles requests and returns a response
    :return: Same, but with permissive CORS headers set
    """

    def _setdefault(obj, key, value):
        if value == None:
            return
        obj.setdefault(key, value)

    def output(*args, **kwargs):
        response = func(*args, **kwargs)
        headers = response.headers
        _setdefault(headers, "Access-Control-Allow-Origin", "*")
        _setdefault(
            headers,
            "Access-Control-Allow-Headers",
            flask.request.headers.get("Access-Control-Request-Headers"),
        )
        _setdefault(
            headers,
            "Access-Control-Allow-Methods",
            flask.request.headers.get("Access-Control-Request-Methods"),
        )
        _setdefault(headers, "Content-Type", "application/json")
        _setdefault(
            headers,
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
        )
        return response

    output.provide_automatic_options = False
    return update_wrapper(output, func)


def dockerflow(flask_app, backend_check):
    """
    ADD ROUTING TO HANDLE DOCKERFLOW APP REQUIREMENTS
    (see https://github.com/mozilla-services/Dockerflow#containerized-app-requirements)
    :param flask_app: THE (Flask) APP
    :param backend_check: METHOD THAT WILL CHECK THE BACKEND IS WORKING AND RAISE AN EXCEPTION IF NOT
    :return:
    """
    global VERSION_JSON

    try:
        VERSION_JSON = File("version.json").read_bytes()

        @cors_wrapper
        def version():
            return Response(
                VERSION_JSON, status=200, headers={"Content-Type": "application/json"}
            )

        @cors_wrapper
        def heartbeat():
            try:
                backend_check()
                return Response(status=200)
            except Exception as e:
                Log.warning("heartbeat failure", cause=e)
                return Response(
                    unicode2utf8(value2json(e)),
                    status=500,
                    headers={"Content-Type": "application/json"},
                )

        @cors_wrapper
        def lbheartbeat():
            return Response(status=200)

        flask_app.add_url_rule(
            str("/__version__"),
            None,
            version,
            defaults={},
            methods=[str("GET"), str("POST")],
        )
        flask_app.add_url_rule(
            str("/__heartbeat__"),
            None,
            heartbeat,
            defaults={},
            methods=[str("GET"), str("POST")],
        )
        flask_app.add_url_rule(
            str("/__lbheartbeat__"),
            None,
            lbheartbeat,
            defaults={},
            methods=[str("GET"), str("POST")],
        )
    except Exception as e:
        Log.error("Problem setting up listeners for dockerflow", cause=e)


VERSION_JSON = None


def add_version(flask_app):
    """
    ADD ROUTING TO HANDLE REQUEST FOR /__version__
    :param flask_app: THE (Flask) APP
    :return:
    """
    try:
        version_info = unicode2utf8(
            value2json(
                {
                    "source": "https://github.com/mozilla/ActiveData/tree/"
                    + git.get_branch(),
                    # "version": "",
                    "commit": git.get_revision(),
                },
                pretty=True,
            )
            + text_type("\n")
        )

        Log.note("Using github version\n{{version}}", version=version_info)

        @cors_wrapper
        def version():
            return Response(
                version_info, status=200, headers={"Content-Type": "application/json"}
            )

        flask_app.add_url_rule(
            str("/__version__"),
            None,
            version,
            defaults={},
            methods=[str("GET"), str("POST")],
        )
    except Exception as e:
        Log.error("Problem setting up listeners for dockerflow", cause=e)


def setup_flask_ssl(flask_app, flask_config):
    """
    SPAWN A NEW THREAD TO RUN AN SSL ENDPOINT
    REMOVES ssl_context FROM flask_config BEFORE RETURNING

    :param flask_app:
    :param flask_config:
    :return:
    """
    if not flask_config.ssl_context:
        return

    ssl_flask = flask_config.copy()
    ssl_flask.debug = False
    ssl_flask.port = 443

    if is_data(flask_config.ssl_context):
        # EXPECTED PEM ENCODED FILE NAMES
        # `load_cert_chain` REQUIRES CONCATENATED LIST OF CERTS
        with TempFile() as tempfile:
            try:
                tempfile.write(
                    File(ssl_flask.ssl_context.certificate_file).read_bytes()
                )
                if ssl_flask.ssl_context.certificate_chain_file:
                    tempfile.write(
                        File(ssl_flask.ssl_context.certificate_chain_file).read_bytes()
                    )
                tempfile.flush()
                tempfile.close()

                context = SSLContext(PROTOCOL_SSLv23)
                context.load_cert_chain(
                    tempfile.name,
                    keyfile=File(ssl_flask.ssl_context.privatekey_file).abspath,
                )

                ssl_flask.ssl_context = context
            except Exception as e:
                Log.error("Could not handle ssl context construction", cause=e)

    def runner(please_stop):
        Log.warning(
            "ActiveData listening on encrypted port {{port}}", port=ssl_flask.port
        )
        flask_app.run(**ssl_flask)

    Thread.run("SSL Server", runner)

    if flask_config.ssl_context and flask_config.port != 80:
        Log.warning(
            "ActiveData has SSL context, but is still listening on non-encrypted http port {{port}}",
            port=flask_config.port,
        )

    flask_config.ssl_context = None


# SEE https://pythonhosted.org/Flask-Session/
SESSION_VARIABLES = {
    "SESSION_COOKIE_NAME": "cookie.name",
    "SESSION_COOKIE_DOMAIN": "cookie.domain",
    "SESSION_COOKIE_PATH": "cookie.path",
    "SESSION_COOKIE_HTTPONLY": "cookie.httponly",
    "SESSION_COOKIE_SECURE": "cookie.secure",
    "PERMANENT SESSION_LIFETIME": "cookie.lifetime",
    "SESSION_SQLITE_TABLE": "store.table",
}


def setup_flask_session(flask_app, session_config):
    """
    :param flask_app:
    :param session_config:
    :return:
    """
    session_config = wrap(session_config)

    filename = session_config.store.filename
    flask_app.config["SESSION_SQLITE"] = Sqlite(filename)
    Log.note("flask.session using {{file}}", file=filename)

    # INJECT CONFIG
    for name, path in SESSION_VARIABLES.items():
        value = session_config[path]
        if exists(value):
            flask_app.config[name] = value

    from pyLibrary.env.flask_session import Session

    Session(flask_app)
