import base64
import hc.html.Widget
import http.server
import time
import urllib.parse
import uuid

from http import HTTPStatus
from types import MappingProxyType


def _encoded_uuid():
    random = uuid.uuid4().bytes
    data = base64.urlsafe_b64encode(random).strip(b"=").decode("utf8")
    return data


class Session:
    def __init__(self):
        self.id = None
        self.data = None
        self.state = None

    @property
    def user(self):
        return self.data["user"]

    @property
    def role(self):
        return self.data["role"]

    @property
    def has_auth(self):
        return self.state == "login"

    @property
    def has_admin(self):
        return self.role == "admin"

    @classmethod
    def from_request(cls, request):
        self = cls()
        self.id = request.get_cookie("sessionid")
        return self

    def to_response(self, response):
        # Persist the session in the browser
        response.send_cookie(
            "sessionid",
            self.id,
            SameSite="Lax",
            Path="/",
        )


class Authenticator:
    def __init__(self):
        self.sessions = {}
        # TODO: param to load auth table

    def _get_user_db(self, user, password):
        # TODO:
        # - lookup user/password in auth table
        # - construct data from auth table details

        fake_user = {
            "admin": {
                "desc": "A Test Admin",
                "role": "admin",
            },
            "user": {
                "desc": "Test User",
                "role": "user",
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
        session = Session.from_request(request)
        if session.id:
            try:
                session.data = self.sessions[session.id]
                session.state = "login"
            except KeyError:
                session.state = "logout"
        return session

    def login2session(self, response, user, password):
        session = Session()
        data = self._get_user_db(user, password)
        if data is None:
            session.state = "bad"
            return session
        session.state = "login"

        session.id = _encoded_uuid()
        session.data = data
        self.sessions[session.id] = session.data

        session.to_response(response)

        return session


class Pages:
    need_auth = False
    need_admin = False

    def __init__(self):
        self.request = 0
        self.elapsed = float()


class PagesMetrics(Pages):
    def handle(self, handler):
        data = []
        for route, page in handler.config.routes.items():
            data += f'site_request_count{{route="{route}"}} {page.request}\n'
            data += f'site_request_seconds{{route="{route}"}} {page.elapsed}\n'

        for route, page in handler.config.routes_subtree.items():
            data += f'site_request_count{{route="{route}"}} {page.request}\n'
            data += f'site_request_seconds{{route="{route}"}} {page.elapsed}\n'

        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data, content_type="text/plain")


class PagesStatic(Pages):
    def __init__(self, body, content_type="text/html"):
        self.body = body
        self.content_type = content_type
        super().__init__()

    def handle(self, handler):
        handler.send_page(
            HTTPStatus.OK,
            self.body,
            content_type=self.content_type,
        )


class RequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, config, *args, **kwargs):
        # save the config object
        self.config = config
        self.time_start = time.time()
        super().__init__(*args, **kwargs)

    # The default method happily appends the responce /after/ adding headers,
    # which results in an invalid reply packet
    def send_response_only(self, code, message=None):
        if hasattr(self, '_headers_buffer'):
            save = self._headers_buffer
            self._headers_buffer = []
        else:
            save = []

        super().send_response_only(code, message)
        self._headers_buffer += save

    def send_cookie(self, name, value, **kwargs):
        parts = [f"{name}={value}"]
        for k, v in kwargs.items():
            if v is None:
                parts.append(k)
            else:
                parts.append(f"{k}={v}")
        cookie = "; ".join(parts)
        self.send_header("Set-Cookie", cookie)

    def get_cookie(self, name):
        value = self.headers.get_param(name, header="Cookie")
        return value

    def get_formdata(self):
        if self.command != "POST":
            # No post data can exist
            return {}

        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        form = urllib.parse.parse_qs(data)
        return form

    def _route2page_obj(self):
        """Returns the object needed to process this page"""
        try:
            return self.config.routes[self.path]
        except KeyError:
            pass

        for prefix, page in self.config.routes_subtree.items():
            if self.path.startswith(prefix):
                return page

        return None

    def _route2render(self):
        """Handle the page all the way to rendering output"""
        self.page = self._route2page_obj()

        if self.page is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        self.page.request += 1

        # TODO: could add page.need_session and avoid getting session
        self.session = self.config.auth.request2session(self)
        if self.page.need_auth:
            if not self.session.has_auth:
                self.send_error(HTTPStatus.UNAUTHORIZED)
                return
        if self.page.need_admin:
            if not self.session.has_admin:
                self.send_error(HTTPStatus.UNAUTHORIZED)
                return

        self.page.handle(self)

    def render_page(self):
        self._route2render()
        self.wfile.flush()

        time_finish = time.time()
        elapsed = time_finish - self.time_start
        try:
            if self.page is not None:
                self.page.elapsed += elapsed
        except AttributeError:
            pass

    def send_page(self, code, body, content_type="text/html"):
        if isinstance(body, str):
            body = body.encode("utf8")
        self.send_response(code)
        self.send_header('Content-type', content_type)
        self.end_headers()
        self.wfile.write(body)


class PagesMap(Pages):
    def handle(self, handler):
        data = []
        data += hc.html.Widget.head("Index")
        data += "<body>"
        data += hc.html.Widget.navbar()
        data += "<ul>"

        for path, page in sorted(handler.config.routes.items()):
            if page.need_auth and not handler.session.has_auth:
                continue
            if page.need_admin and not handler.session.has_admin:
                continue
            data += f"""
             <li><a href="{path}">{path}</a>
            """

        data += """
         </ul>
         </body>
         </html>
        """

        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)
