# encoding: utf-8
#
from uuid import uuid4

from flask.sessions import SessionInterface as FlaskSessionInterface
from mo_kwargs import override

from mo_dots import Data, wrap, exists, is_data
from mo_future import first
from mo_json import json2value, value2json
from mo_logs import Log
from mo_threads import Till
from mo_threads.threads import register_thread
from mo_times import Date
from mo_times.dates import parse
from pyLibrary.sql import SQL_WHERE, sql_list, SQL_SET, SQL
from pyLibrary.sql.sqlite import (
    sql_create,
    sql_eq,
    quote_column,
    sql_query,
    sql_insert,
    Sqlite,
    quote_value,
)

DEBUG = True


class NoSigner(object):
    def sign(self, value):
        return value

    def unsign(self, value):
        return value


class SqliteSessionInterface(FlaskSessionInterface):
    """STORE SESSION DATA IN SQLITE

    :param db: Sqlite database
    :param table: The table name you want to use.
    :param use_signer: Whether to sign the session id cookie or not.
    :param permanent: Whether to use permanent session or not.
    """
    @override
    def __init__(self, flask_app, db, cookie, table="sessions", use_signer=False):
        if is_data(db):
            self.db = Sqlite(db)
        else:
            self.db = db
        self.table = table
        self.cookie = cookie
        if use_signer:
            if not flask_app.secret_key:
                Log.error("Expecting flask secret key")
            from itsdangerous import Signer
            self.signer = Signer(flask_app.secret_key, salt="flask-session", key_derivation="hmac")
        else:
            self.signer = NoSigner()

        if not self.db.about(self.table):
            self.setup()

    def monitor(self, please_stop):
        while not please_stop:
            # Delete expired session
            try:
                with self.db.transaction() as t:
                    t.execute(
                        "DELETE FROM "
                        + quote_column(self.table)
                        + SQL_WHERE
                        + quote_column("expiry")
                        + SQL(" < ")
                        + quote_value(Date.now().unix)
                    )
            except Exception as e:
                Log.warning("problem with session expiry", cause=e)
            (please_stop | Till(seconds=60)).wait()

    def _generate_sid(self):
        return str(uuid4())

    def setup(self):
        with self.db.transaction() as t:
            t.execute(
                sql_create(
                    self.table,
                    {"session_id": "TEXT", "data": "TEXT", "expiry": "NUMBER"},
                )
            )

    @register_thread
    def open_session(self, app, request):
        now = Date.now().unix
        session_id = request.cookies.get(app.session_cookie_name)
        DEBUG and Log.note("got session_id {{session|quote}}", session=session_id)
        if not session_id:
            session = Data(session_id=self._generate_sid(), permanent=True)
            DEBUG and Log.note("return session {{session}}", session=session)
            return session
        session_id = self.signer.unsign(session_id.encode('utf8')).decode('utf8')

        result = self.db.query(
            sql_query({"from": self.table, "where": {"eq": {"session_id": session_id}}})
        )
        saved_record = first(Data(zip(result.header, r)) for r in result.data)
        if not saved_record:
            DEBUG and Log.note("Did not find session in db {{session}}", session=session_id)
            return Data(session_id=session_id, permanent=True)

        if saved_record.expiry <= now:
            session = Data(session_id=self._generate_sid(), permanent=True)
            DEBUG and Log.note("return session {{session}}", session=session)
            return session

        DEBUG and Log.note("record from db {{session}}", session=saved_record)
        session = json2value(saved_record.data)
        return session

    @register_thread
    def save_session(self, app, session, response):
        if not session:
            return
        if not session.session_id:
            session.session_id = self._generate_sid()
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

        session_id = self.signer.sign(session_id.encode('utf8')).decode('utf8')

        DEBUG and Log.note("transmit cookie {{session}}", session=session_id)
        response.set_cookie(
            app.session_cookie_name,
            session_id,
            expires=expires,
            httponly=self.get_cookie_httponly(app),
            domain=self.get_cookie_domain(app),
            path=self.get_cookie_path(app),
            secure=self.get_cookie_secure(app),
        )


def setup_flask_session(flask_app, session_config):
    """
    SETUP FlASK SESSION MANAGEMENT
    :param flask_app: USED TO PULL THE flask_app.config
    :param session_config: CONFIGURATION
    :return:
    """
    session_config = wrap(session_config)
    # INJECT CONFIG INTO FLASK VARIABLES
    for name, path in SESSION_VARIABLES.items():
        value = session_config[path]
        if exists(value):
            flask_app.config[name] = value

    flask_app.session_interface = SqliteSessionInterface(flask_app, kwargs=session_config)


# SEE https://pythonhosted.org/Flask-Session/
SESSION_VARIABLES = {
    "SESSION_COOKIE_NAME": "cookie.name",
    "SESSION_COOKIE_DOMAIN": "cookie.domain",
    "SESSION_COOKIE_PATH": "cookie.path",
    "SESSION_COOKIE_HTTPONLY": "cookie.httponly",
    "SESSION_COOKIE_SECURE": "cookie.secure",
    "PERMANENT SESSION_LIFETIME": "cookie.lifetime"
}
