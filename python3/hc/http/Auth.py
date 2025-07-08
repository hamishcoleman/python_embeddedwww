import base64
import hashlib
import hmac
import json
import sqlite3
import time

from types import MappingProxyType


def _decode_b64(data):
    # Just give me a b64decode that ignores the padding, kthx:wq
    return base64.urlsafe_b64decode(data + b"===")


def _encode_jsonb64(data):
    return base64.urlsafe_b64encode(
        json.dumps(
            data,
            separators=(",", ":")
        ).encode("ascii")
    ).rstrip(b"=")


def _data2simplejwt(secret, data):
    header = {
        "alg": "HS256",
        "typ": "JWT",
    }
    header_enc = _encode_jsonb64(header)
    data_enc = _encode_jsonb64(data)
    sig = hmac.digest(secret, header_enc + b"." + data_enc, hashlib.sha256)
    sig_enc = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return header_enc + b"." + data_enc + b"." + sig_enc


def _simplejwt2data(secret, jwt):
    header_enc, data_enc, sig_enc = jwt.split(b".")
    header = json.loads(_decode_b64(header_enc))
    if header["typ"] != "JWT":
        raise ValueError("unexpected jwt typ")
    if header["alg"] != "HS256":
        raise ValueError("unexpected jwt alg")

    sig1 = _decode_b64(sig_enc)
    sig2 = hmac.digest(secret, header_enc + b"." + data_enc, hashlib.sha256)

    if sig1 != sig2:
        raise ValueError("Failed jwt validation")

    return json.loads(_decode_b64(data_enc))


class Session:
    """
    Information about the current user login and their session is accessed
    via a Session object.

    During normal requests, the Authenticator will create the session object
    from the request.  This fields will be populated by the Authenticator and
    then this information is available to any page handlers.

    During login, the Authenticator will create the session object from its
    login information and ask the Session object to update the response.
    """
    def __init__(self):
        self.id = None
        self.data = None
        self.state = None

    @property
    def user(self):
        if self.data is None:
            return None
        return self.data["user"]

    @property
    def has_auth(self):
        return self.state == "login"

    @property
    def has_admin(self):
        return bool(self.data["admin"])

    @classmethod
    def from_request(cls, request):
        self = cls()
        self.id = request.get_cookie("sessionid")
        return self

    def to_response(self, response):
        # Persist the session in the browser
        #
        # TODO: if client made request using SSL, then the cookie should be
        # set to Secure as well
        response.send_cookie(
            "sessionid",
            self.id,
            SameSite="Strict",
            HttpOnly=None,
            Path="/",
        )

    def del_cookie(self, response):
        response.send_cookie(
            "sessionid",
            "deleted",
            SameSite="Strict",
            HttpOnly=None,
            Path="/",
            expires="Thu, 01 Jan 1970 00:00:00 GMT",
        )


class Base:
    """
    The Authenticator object is used on all requests and logins to validate
    all the details.

    This is currently essentially a dummy implementation.

    It is expected that things like persisting session state into cookies or
    authenticating with JWT can be implemented by subclassing this class.
    """

    def end_session(self, session, handler=None):
        """
        This is called to invalidate a session ID.  Effectively serving as a
        logout.  It is expected to flag the session ID as invalid - requiring
        credentials to be presented to start using again.  It should flush any
        session settings changes or caches.

        Since ending the session might require deleting a cookie, the handler
        can be passed in as well
        """
        raise NotImplementedError

    def replace_data(self, src, dst):
        """
        Copy the session information out of one session ID into another.
        Since session data is intended to be readonly, a helper is needed
        to provide any required deepcopy or object recreation.

        This is expected to be used to allow an Admin to "clone" somebody
        else's existing session - for debugging or support.
        It is an experimental idea and should be used carefully.
        """
        raise NotImplementedError

    def request2session(self, request):
        """
        Given a RequestHandler object, extract information from the request
        and return a Session object describing this session.
        Only previously authenticated and active sessions should be returned.
        """
        raise NotImplementedError

    def login2session(self, response, user, password):
        """
        Given some authentication information (currently username and password)
        - perform checks to confirm their validity
        - Update the response object with any needed data (expected to be used
          to set a cookie)
        """
        raise NotImplementedError


class JWTCookie(Base):
    def __init__(self):
        super().__init__()
        self.secret = b"secret"

    def end_session(self, session, handler=None):
        if session is None:
            return

        if handler is not None:
            session.del_cookie(handler)

        session.state = "logout"

    def request2session(self, request, session=None):
        if session is None:
            raise ValueError("Need session")

        # try decoding jwt
        try:
            session.data = _simplejwt2data(
                self.secret,
                session.id.encode("ascii")
            )
            session.state = "login"
        except ValueError:
            session.state = "logout"

        return session

    def login2session(self, response, user, password, data=None):
        # TODO:
        # this doesnt check the user and password, maybe it shouldnt be
        # passed those?
        session = Session()

        session.id = _data2simplejwt(self.secret, data).decode("ascii")
        session.data = data
        session.state = "login"

        session.to_response(response)

        return session


class Simple(JWTCookie):
    def __init__(self):
        super().__init__()

        # A ram cache
        # TODO: param to load auth table
        self.sessions = {}

    def end_session(self, session, handler=None):
        super().end_session(session, handler)

        if session is None:
            return
        del self.sessions[session.id]

    def replace_data(self, src, dst):
        # This probably needs fixing when using jwt cookies
        self.sessions[dst.id] = self.sessions[src.id]

    def request2session(self, request):
        session = Session.from_request(request)
        if not session.id:
            # We couldnt get a session
            # TODO: maybe return None
            return session

        if session.data is not None:
            # We managed to populate the data from the request already
            return session

        # The session could be created - but not populated - from the
        # request, so we try to populate it

        # First, try our RAM session cache
        try:
            session.data = self.sessions[session.id]
            session.state = "login"
        except KeyError:
            super().request2session(request, session=session)

            if session.has_auth:
                # Cache the readonly version
                self.sessions[session.id] = MappingProxyType(session.data)

        return session

    def login2session(self, response, user, password):
        data = self._get_user_db(user, password)
        if data is None:
            # Could not find this user in our data
            session = Session()
            session.state = "bad"
            return session

        session = super().login2session(response, user, password, data=data)

        # We enforce that the session data is readonly as that will allow
        # the use of JWT (or similar) to populate the session data
        self.sessions[session.id] = MappingProxyType(session.data)

        return session

    def _crypt_pass(self, password, salt, iterations):
        """Return the one-way crypted password string

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
        """Check if a cleartext password matches the crypted string

        >>> check("1", "pbkdf2_sha256$10000$r9wsGVOV$vBYGQzpnmf3y7hek1CvhInzEbi/GNXJUwXh4ufxrMUA=")
        True

        >>> check("1", "pbkdf2_sha256$260000$5o4NaW9tV4fAB7a80vwOUx$EUGNGeMxRK16YRFtIOWlJaBRlfG+6y6LP3eDxQDgRq8=")
        True
        """  # noqa: E501
        algorithm, iterations, salt, hash1 = crypted.split("$")
        iterations = int(iterations)
        crypted2 = self._crypt_pass(password, salt, iterations)
        return crypted == crypted2


class Test(Simple):
    """A test authenticator, with a hardcoded dummy user database"""

    def _get_user_db(self, user, password):
        # TODO:
        # - lookup user/password in auth table
        # - construct data from auth table details
        # - use fields that look more like JWT

        fake_user = {
            "admin": {
                "desc": "A Test Admin",
                "admin": True,
            },
            "user": {
                "desc": "Test User",
                "admin": False,
            },
        }
        fake_pass = {
            "admin": "1234",
            "user": "1234",
        }

        if user not in fake_pass:
            return None
        if password != fake_pass[user]:
            return None

        data = fake_user[user].copy()
        data["user"] = user
        data["createdat"] = time.time()

        return data


class Sqlite(Simple):
    def __init__(self, dbfile):
        super().__init__()

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

        return data
