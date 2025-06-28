import base64
import hashlib
import hc.http.WebSite
import sqlite3
import time

from types import MappingProxyType


class Authenticator(hc.http.WebSite.AuthenticatorBase):
    def __init__(self, dbfile):
        self.sessions = {}  # A ram cache
        self.con = sqlite3.connect(dbfile)

        self.con.execute("""
            CREATE TABLE IF NOT EXISTS auth(
                username TEXT PRIMARY KEY,
                password TEXT,
                enable INTEGER,
                admin INTEGER
            )
        """)

    def _get_user_db(self, user, password):
        cur = self.con.execute(
            """
            SELECT password, admin
            FROM auth
            WHERE username = ? AND enable = TRUE
            """,
            [user],
        )
        rows = cur.fetchall()

        if len(rows) != 1:
            # len 0 means unknown or disabled username
            # len >1 means something went wrong
            return None

        if not self._check_pass(password, rows[0][0]):
            # password mismatch
            return None

        data = {}
        data["admin"] = bool(rows[0][1])
        data["user"] = user
        data["createdat"] = time.time()

        # We enforce that the session data is readonly as that will allow
        # the use of JWT (or similar) to populate the session data
        data = MappingProxyType(data)
        return data

    def end_session(self, session):
        if session is None:
            return
        del self.sessions[session.id]
        session.state = "logout"

    def replace_data(self, src, dst):
        self.sessions[dst.id] = self.sessions[src.id]

    def request2session(self, request):
        session = hc.http.WebSite.Session.from_request(request)
        if session.id and session.data is None:
            # The session could be created - but not populated - from the
            # request, so we try to populate it
            try:
                session.data = self.sessions[session.id]
                session.state = "login"
            except KeyError:
                session.state = "logout"
        return session

    def login2session(self, response, user, password):
        session = hc.http.WebSite.Session()
        data = self._get_user_db(user, password)
        if data is None:
            session.state = "bad"
            return session
        session.state = "login"

        session.id = hc.http.WebSite._encoded_uuid()
        session.data = data
        self.sessions[session.id] = session.data

        session.to_response(response)

    def _crypt_pass(self, password, salt, iterations):
        """Return the password string

        >>> crypt("1", "r9wsGVOV", 10000)
        'pbkdf2_sha256$10000$r9wsGVOV$vBYGQzpnmf3y7hek1CvhInzEbi/GNXJUwXh4ufxrMUA='
        """
        algorithm = "pbkdf2_sha256"
        digest = hashlib.sha256().name
        hash = base64.b64encode(hashlib.pbkdf2_hmac(
                digest,
                password.encode(),
                salt.encode(),
                iterations
        )).decode("ascii").strip()
        return "%s$%d$%s$%s" % (algorithm, iterations, salt, hash)

    def _check_pass(self, password, crypted):
        """Check a password

        >>> check("1", "pbkdf2_sha256$10000$r9wsGVOV$vBYGQzpnmf3y7hek1CvhInzEbi/GNXJUwXh4ufxrMUA=")
        True

        >>> check("1", "pbkdf2_sha256$260000$5o4NaW9tV4fAB7a80vwOUx$EUGNGeMxRK16YRFtIOWlJaBRlfG+6y6LP3eDxQDgRq8=")
        True
        """  # noqa: E501
        algorithm, iterations, salt, hash1 = crypted.split("$")
        iterations = int(iterations)
        crypted2 = self._crypt_pass(password, salt, iterations)
        return crypted == crypted2
