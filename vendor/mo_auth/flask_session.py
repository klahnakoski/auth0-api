# encoding: utf-8
#
from uuid import uuid4

from flask.sessions import SessionInterface as FlaskSessionInterface

from mo_dots import Data, wrap, exists, is_data
from mo_future import first
from mo_json import json2value, value2json
from mo_kwargs import override
from mo_logs import Log
from mo_threads import Till
from mo_threads.threads import register_thread
from mo_times import Date
from mo_times.dates import parse, RFC1123
from pyLibrary.sql import SQL_WHERE, sql_list, SQL_SET
from pyLibrary.sql.sqlite import (
    sql_create,
    sql_eq,
    quote_column,
    sql_query,
    sql_insert,
    Sqlite,
    sql_lt)

DEBUG = True


def generate_sid():
    """
    GENERATE A UNIQUE SESSION ID
    """
    return str(uuid4())



class SqliteSessionInterface(FlaskSessionInterface):
    """STORE SESSION DATA IN SQLITE

    :param db: Sqlite database
    :param table: The table name you want to use.
    :param use_signer: Whether to sign the session id cookie or not.
    """

    @override
    def __init__(self, flask_app, db, cookie, table="sessions", use_signer=False):
        if is_data(db):
            self.db = Sqlite(db)
        else:
            self.db = db
        self.table = table
        self.cookie = cookie

        if not self.db.about(self.table):
            self.setup()

    def setup_session(self, session):
        session.session_id = generate_sid()
        session.permanent = True
        session.expiry = Date.now().unix + self.cookie.lifetime

    def monitor(self, please_stop):
        while not please_stop:
            # Delete expired session
            try:
                with self.db.transaction() as t:
                    t.execute(
                        "DELETE FROM "
                        + quote_column(self.table)
                        + SQL_WHERE
                        + sql_lt(expiry=Date.now().unix)
                    )
            except Exception as e:
                Log.warning("problem with session expiry", cause=e)
            (please_stop | Till(seconds=60)).wait()

    def setup(self):
        with self.db.transaction() as t:
            t.execute(
                sql_create(
                    self.table,
                    {
                        "session_id": "TEXT PRIMARY KEY",
                        "data": "TEXT",
                        "expiry": "NUMBER",
                    },
                )
            )

    def make_cookie(self, session):
        return {
            self.cookie.name: session.session_id,
            "Domain": self.cookie.domain,
            "Path": self.cookie.path,
            "Secure": self.cookie.secure,
            "HttpOnly": self.cookie.httponly,
            "Expires": parse(session.expiry).format(RFC1123)
        }

    @register_thread
    def open_session(self, app, request):
        now = Date.now().unix
        session_id = request.cookies.get(app.session_cookie_name)
        DEBUG and Log.note("got session_id {{session|quote}}", session=session_id)
        if not session_id:
            return Data()

        result = self.db.query(
            sql_query({"from": self.table, "where": {"eq": {"session_id": session_id}}})
        )
        saved_record = first(Data(zip(result.header, r)) for r in result.data)
        if not saved_record or saved_record.expiry <= now:
            return Data()

        DEBUG and Log.note("record from db {{session}}", session=saved_record)
        session = json2value(saved_record.data)
        return session

    @register_thread
    def save_session(self, app, session, response):
        if not session or not session.keys():
            return
        if not session.session_id:
            session.session_id = generate_sid()
            session.permanent = True
        DEBUG and Log.note("save session {{session}}", session=session)

        session_id = session.session_id
        result = self.db.query(
            sql_query({"from": self.table, "where": {"eq": {"session_id": session_id}}})
        )
        saved_record = first(Data(zip(result.header, r)) for r in result.data)
        expires = self.get_expiration_time(app, session)
        if saved_record:
            DEBUG and Log.note("found session {{session}}", session=saved_record)

            saved_record.data = value2json(session)
            saved_record.expiry = parse(expires).unix
            with self.db.transaction() as t:
                t.execute(
                    "UPDATE "
                    + quote_column(self.table)
                    + SQL_SET
                    + sql_list(sql_eq(**{k: v}) for k, v in saved_record.items())
                    + SQL_WHERE
                    + sql_eq(session_id=session_id)
                )
        else:
            new_record = {
                "session_id": session_id,
                "data": value2json(session),
                "expiry": parse(expires).unix,
            }
            DEBUG and Log.note("new record for db {{session}}", session=new_record)
            with self.db.transaction() as t:
                t.execute(sql_insert(self.table, new_record))


def setup_flask_session(flask_app, session_config):
    """
    SETUP FlASK SESSION MANAGEMENT
    :param flask_app: USED TO PULL THE flask_app.config
    :param session_config: CONFIGURATION
    :return: THE SESSION MANAGER
    """
    session_config = wrap(session_config)
    # INJECT CONFIG INTO FLASK VARIABLES
    for name, path in SESSION_VARIABLES.items():
        value = session_config[path]
        if exists(value):
            flask_app.config[name] = value

    output = flask_app.session_interface = SqliteSessionInterface(
        flask_app, kwargs=session_config
    )
    return output


# SEE https://pythonhosted.org/Flask-Session/
SESSION_VARIABLES = {
    "SESSION_COOKIE_NAME": "cookie.name",
    "SESSION_COOKIE_DOMAIN": "cookie.domain",
    "SESSION_COOKIE_PATH": "cookie.path",
    "SESSION_COOKIE_HTTPONLY": "cookie.httponly",
    "SESSION_COOKIE_SECURE": "cookie.secure",
    "PERMANENT SESSION_LIFETIME": "cookie.lifetime",
}
