import base64
import hc.html.Widget
import hc.http.Pages
import hc.http.TBF
import http.server
import time
import urllib.parse
import uuid

from http import HTTPStatus


def _encoded_uuid():
    """
    Generate a random uuid and encode it for easy use.
    """
    # TODO:
    # - denser encoding would be better

    random = uuid.uuid4().bytes
    data = base64.urlsafe_b64encode(random).strip(b"=").decode("utf8")
    return data


class Config:
    """
    Provide site configuration.  Each instance of RequestHandler will be
    passed this config, so it could be used for Website-Wide configuration.

    Normally it is expected that the object instances in the routes dicts will
    have been created with access to any persistant state information for the
    operation of the site and the Config object is for the infrastructure.
    """
    def __init__(self):
        self.Widget = hc.html.Widget.Default
        self.auth = None
        self.routes = {}
        self.routes_subtree = {}


class RequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, config, *args, **kwargs):
        # save the config object
        self.config = config
        self.time_start = time.time()
        self._form = None
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

    @property
    def form(self):
        if self._form is not None:
            # we have already loaded the form, so return that
            return self._form

        if self.command != "POST":
            # No post data can exist
            return {}

        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        self._form = urllib.parse.parse_qs(data)
        return self._form

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

    def _checkperms(self, page):
        """Check the Page attrs against the request session"""
        if page.need_auth:
            if not self.session.has_auth:
                return False
        if page.need_admin:
            if not self.session.has_admin:
                return False
        return True

    def _route2render(self):
        """Handle the page all the way to rendering output"""
        self.page = self._route2page_obj()

        if self.page is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        self.page.request += 1

        if not self.page.tbf.withdraw(1):
            # TODO: increment error count
            self.send_error(HTTPStatus.TOO_MANY_REQUESTS)
            return

        # TODO: could add page.need_session and avoid getting session
        self.session = self.config.auth.request2session(self)
        if not self._checkperms(self.page):
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return

        page_method_name = 'do_' + self.command
        if not hasattr(self.page, page_method_name):
            self.send_error(HTTPStatus.NOT_IMPLEMENTED)
            return
        page_handler = getattr(self.page, page_method_name)
        page_handler(self)

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

    def send_page(self, code, body, content_type="text/html; charset=utf-8"):
        if isinstance(body, list):
            body = [str(x) for x in body]
            body = "".join(body)
        if isinstance(body, str):
            body = body.encode("utf8")
        self.send_response(code)
        self.send_header('Content-type', content_type)
        self.end_headers()
        self.wfile.write(body)
