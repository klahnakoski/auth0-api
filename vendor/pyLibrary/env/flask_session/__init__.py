# encoding: utf-8
#
from uuid import uuid4

from flask.sessions import SessionInterface as FlaskSessionInterface
from itsdangerous import Signer, want_bytes

from mo_dots import Data, wrap, exists
from mo_future import first
from mo_json import json2value, value2json
from mo_logs import Log
from mo_threads.threads import register_thread
from mo_times import Date
from mo_times.dates import parse
from pyLibrary.sql import SQL_WHERE, sql_list, SQL_SET
from pyLibrary.sql.sqlite import sql_create, sql_eq, quote_column, sql_query, sql_insert, Sqlite


class SqliteSessionInterface(FlaskSessionInterface):
    """STORE SESSION DATA IN SQLITE

    :param db: Sqlite database
    :param table: The table name you want to use.
    :param use_signer: Whether to sign the session id cookie or not.
    :param permanent: Whether to use permanent session or not.
    """

    def __init__(self, db, table, use_signer=False):
        self.db = db
        self.table = table
        self.use_signer = use_signer
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
        Log.note("got session_id {{session|quote}}", session=session_id)
        if not session_id:
            output = Data(session_id=self._generate_sid(), permanent=True)
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
        saved_record = first(Data(zip(result.header, r)) for r in result.data)
        if not saved_record:
            Log.note("Did not find session in db {{session}}", session=session_id)
            return Data(session_id=session_id, permanent=True)

        if saved_record.expiry <= now:
            # Delete expired session
            with self.db.transaction() as t:
                t.execute(
                    "DELETE FROM "
                    + quote_column(self.table)
                    + SQL_WHERE
                    + sql_eq(session_id=session_id)
                )
            saved_record = None
        Log.note("record from db {{session}}", session=saved_record)
        session = json2value(saved_record.data)
        return session

    @register_thread
    def save_session(self, app, session, response):
        if not session:
            return
        if not session.session_id:
            session.session_id = self._generate_sid()
        Log.note("save session {{session}}", session=session)

        session_id = session.session_id
        result = self.db.query(
            sql_query({"from": self.table, "where": {"eq": {"session_id": session_id}}})
        )
        saved_record = first(Data(zip(result.header, r)) for r in result.data)
        expires = self.get_expiration_time(app, session)
        if saved_record:
            Log.note("found session {{session}}", session=saved_record)

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
            Log.note("new record for db {{session}}", session=new_record)
            with self.db.transaction() as t:
                t.execute(sql_insert(self.table, new_record))

        if self.use_signer:
            session_id = self._get_signer(app).sign(want_bytes(session_id))

        Log.note("transmite cookie {{session}}", session=session_id)
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
    filename = session_config.store.filename
    Log.note("flask.session using {{file}}", file=filename)

    # INJECT CONFIG
    for name, path in SESSION_VARIABLES.items():
        value = session_config[path]
        if exists(value):
            flask_app.config[name] = value

    from pyLibrary.env.flask_session import SqliteSessionInterface
    flask_app.session_interface = SqliteSessionInterface(
        db=Sqlite(filename),
        table=session_config.store.table,
        use_signer=flask_app.config.get("SESSION_USE_SIGNER")
    )

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


