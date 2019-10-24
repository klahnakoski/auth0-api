# -*- coding: utf-8 -*-
"""
    flask_session.sessions
    ~~~~~~~~~~~~~~~~~~~~~~

    Server-side Sessions and SessionInterfaces.

    :copyright: (c) 2014 by Shipeng Feng.
    :license: BSD, see LICENSE for more details.
"""
from uuid import uuid4

from mo_dots.datas import register_data
from mo_times.dates import parse

from mo_dots import Data
from mo_future import first
from mo_json import json2value, value2json
from mo_logs import Log
from mo_times import Date
from pyLibrary.sql import SQL_WHERE, sql_list, SQL_SET
from pyLibrary.sql.sqlite import sql_create, sql_eq, quote_column, sql_query, sql_insert

from flask.sessions import SessionInterface as FlaskSessionInterface
from flask.sessions import SessionMixin
from werkzeug.datastructures import CallbackDict
from itsdangerous import Signer, want_bytes


def total_seconds(td):
    return td.days * 60 * 60 * 24 + td.seconds


class ServerSideSession(CallbackDict, SessionMixin):
    """Baseclass for server-side based sessions."""

    def __init__(self, initial=None, session_id=None, permanent=None):
        def on_update(self):
            self.modified = True

        CallbackDict.__init__(self, initial, on_update)
        self.session_id = session_id
        if permanent:
            self.permanent = permanent
        self.modified = False


register_data(ServerSideSession)


class SqliteSessionInterface(FlaskSessionInterface):
    """Uses the Flask-SQLAlchemy from a flask app as a session backend.

    .. versionadded:: 0.2

    :param app: A Flask app instance.
    :param db: A Flask-SQLAlchemy instance.
    :param table: The table name you want to use.
    :param use_signer: Whether to sign the session id cookie or not.
    :param permanent: Whether to use permanent session or not.
    """

    def __init__(self, app, db, table, use_signer=False, permanent=True):
        self.db = db
        self.table = table
        self.use_signer = use_signer
        self.permanent = permanent
        if not self.db.about(self.table):
            self.setup()

    def _generate_sid(self):
        return str(uuid4())

    def _get_signer(self, app):
        if not app.secret_key:
            return None
        return Signer(app.secret_key, salt="flask-session", key_derivation="hmac")

    def setup(self):
        with self.db.transaction() as t:
            t.execute(
                sql_create(
                    self.table,
                    {"session_id": "TEXT", "data": "TEXT", "expiry": "NUMBER"},
                )
            )

    def open_session(self, app, request):
        now = Date.now().unix
        session_id = request.cookies.get(app.session_cookie_name)
        Log.note("got session {{session}}", session=session_id)
        if not session_id:
            session_id = self._generate_sid()
            output = ServerSideSession(session_id=session_id, permanent=self.permanent)
            Log.note("return session {{session}}", session=output)
            return output
        if self.use_signer:
            signer = self._get_signer(app)
            if signer is None:
                Log.error("Expecting a signer")
            sid_as_bytes = signer.unsign(session_id)
            session_id = sid_as_bytes.decode("utf8")

        result = self.db.query(
            sql_query({"from": self.table, "where": {"eq": {"session_id": session_id}}})
        )
        saved_session = first(Data(zip(result.header, r)) for r in result.data)

        if saved_session and saved_session.expiry <= now:
            # Delete expired session
            with self.db.transaction() as t:
                t.execute(
                    "DELETE FROM "
                    + quote_column(self.table)
                    + SQL_WHERE
                    + sql_eq(session_id=session_id)
                )
            saved_session = None
        if saved_session:
            data = json2value(saved_session.data)
            return ServerSideSession(data, session_id=session_id)
        return ServerSideSession(session_id=session_id, permanent=self.permanent)

    def save_session(self, app, session, response):
        if not session:
            return
        Log.note("save session {{session}}", session=session)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        session_id = session.session_id
        result = self.db.query(
            sql_query({"from": self.table, "where": {"eq": {"session_id": session_id}}})
        )
        saved_session = first(Data(zip(result.header, r)) for r in result.data)
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        expires = self.get_expiration_time(app, session)
        if saved_session:
            saved_session.data = value2json(session)
            saved_session.expiry = expires
            with self.db.transaction() as t:
                t.execute(
                    "UPDATE "
                    + quote_column(self.table)
                    + SQL_SET
                    + sql_list(sql_eq(**{k: v}) for k, v in saved_session.items())
                    + SQL_WHERE
                    + sql_eq(session_id=session_id)
                )
        else:
            with self.db.transaction() as t:
                t.execute(
                    sql_insert(
                        self.table,
                        {
                            "session_id": session_id,
                            "data": value2json(session),
                            "expiry": parse(expires).unix,
                        },
                    )
                )

        if self.use_signer:
            session_id = self._get_signer(app).sign(want_bytes(session_id))
        response.set_cookie(
            app.session_cookie_name,
            session_id,
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
        )
