#!/usr/bin/env python3
"""Simple http website providing some session helper services"""
#
# TODO:
# - HTTP/1.1, requires content length
# - ratelimit uuid generation

import argparse
import base64
import functools
import http.server
import signal
import socketserver
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


class Widget:
    @classmethod
    def style(cls):
        r = []
        r += '<link rel="stylesheet" type="text/css" href="/style.css" />'
        return r

    @classmethod
    def head(cls, title):
        r = []
        r += """<!DOCTYPE html>
         <html>
         <head>
        """
        r += f"<title>{title}</title>"
        r += Widget.style()
        r += "</head>"
        return r

    @classmethod
    def navbar(cls):
        r = []
        r += '<a href="/sitemap">sitemap</a>'
        # TODO: the above hardcodes the location of the sitemap
        return r

    @classmethod
    def show_dict(cls, d, actions):
        r = []
        r += """
         <table class="w">
          <tr>
           <th>ID
           <th>Data
           <th>Action
        """

        for k, v in d.items():
            r += f"""
             <tr>
              <td class="w">{k}
              <td class="w">{v}
              <td>
            """
            for action in actions:
                r += f"""
                 <button name="a" value="{action}/{k}">{action}</button>
                """

        r += """
         </table>
        """
        return r

    @classmethod
    def show_dictlist(cls, dl, actions):
        r = []
        r += """
         <table>
          <tr>
           <th>ID
           <th>Data
           <th>Action
        """

        for i in range(len(dl)):
            r += f"""
             <tr>
              <td class="w">{i}
              <td class="w">{dl[i]}
              <td>
            """
            for action in actions:
                r += f"""
                 <button name="a" value="{action}/{i}">{action}</button>
                """

        r += """
         </table>
        """
        return r


class Pages:
    need_auth = False
    need_admin = False


class PagesStatic(Pages):
    def __init__(self, body, content_type="text/html"):
        self.body = body
        self.content_type = content_type

    def handle(self, handler):
        handler.send_page(
            HTTPStatus.OK,
            self.body,
            content_type=self.content_type,
        )


class BetterHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, config, *args, **kwargs):
        # save the config object
        self.config = config
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
        page = self._route2page_obj()

        if page is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        # TODO: could add page.need_session and avoid getting session
        self.session = self.config.auth.request2session(self)
        if page.need_auth:
            if not self.session.has_auth:
                self.send_error(HTTPStatus.UNAUTHORIZED)
                return
        if page.need_admin:
            if not self.session.has_admin:
                self.send_error(HTTPStatus.UNAUTHORIZED)
                return

        page.handle(self)

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
        data += Widget.head("Index")
        data += "<body>"
        data += Widget.navbar()
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


class PagesLogin(Pages):
    def handle(self, handler):
        if handler.command == "POST":
            form = handler.get_formdata()
            action = form[b"a"][0].decode("utf8")

            if action == "login":
                user = form[b"user"][0].decode("utf8")
                password = form[b"pass"][0].decode("utf8")
                handler.session = handler.config.auth.login2session(
                    handler,
                    user,
                    password
                )

                if handler.session.has_auth:
                    # Make reloading nicer
                    handler.send_header("Location", handler.path)
                    handler.send_error(HTTPStatus.SEE_OTHER)
                    return
            else:
                try:
                    handler.config.auth.end_session(handler.session)
                except KeyError:
                    handler.session.state = "bad"

        data = []
        data = Widget.head("Login")
        data += "<body>"
        data += Widget.navbar()
        data += """
           <form method="post">
            <table>
        """

        data += f"""
          <tr>
           <th align=right>Client:
           <td>{handler.client_address}
        """

        # TODO:
        # - if we are behind a proxy, use the header instead of the
        #   client_address

        # TODO:
        # if handler.client_address[0] == "127.0.0.1":
        #     data += pid/processname/args

        host = handler.headers["Host"]
        data += f"""
          <tr>
           <th align=right>Host:
           <td>{host}
        """

        cookie_uuid = handler.get_cookie("uuid")
        if cookie_uuid:
            data += f"""
            <tr>
             <th align=right>UUID:
             <td>{cookie_uuid}
            """

        if handler.session.has_auth:
            data += f"""
            <tr>
            <tr>
             <th align=right><label for="user">Username:</label>
             <td>{handler.session.user}
            <tr>
            <tr>
             <th>
             <td align=right><button name="a" value="logout">Logout</button>
            """
        else:
            data += """
            <tr>
            <tr>
             <th align=right><label for="user">Username:</label>
             <td><input type="text" id="user" name="user" autofocus>
            <tr>
             <th align=right><label for="pass">Password:</label>
             <td><input type="password" id="pass" name="pass">
            <tr>
             <th>
             <td align=right><button name="a" value="login">Login</button>
            """

        if handler.session.state == "bad":
            data += """
            <tr>
             <th>
             <td>Bad Attempt
            """
            code = HTTPStatus.UNAUTHORIZED
        else:
            code = HTTPStatus.OK

        data += """
           </table>
          </form>
          </body>
        """

        data = "".join(data)
        handler.send_page(code, data)


class PagesAuthList(Pages):
    need_auth = True
    need_admin = True

    def handle(self, handler):
        if handler.command == "POST":
            form = handler.get_formdata()
            action = form[b"a"][0].decode("utf8")

            action, action_id = action.split("/")
            action_session = Session()
            action_session.id = action_id

            if action == "del":
                handler.config.auth.end_session(action_session)
            elif action == "clone":
                handler.config.auth.replace_data(action_session, self.session)

                # TODO: hardcodes the location of this page
                handler.send_header("Location", "login")
                handler.send_error(HTTPStatus.SEE_OTHER)
                return
            else:
                handler.send_error(HTTPStatus.BAD_REQUEST)
                return

        data = []
        data += Widget.head("Sessions")
        data += "<body>"
        data += Widget.navbar()
        data += '<form method="post">'

        data += Widget.show_dict(
            handler.config.auth.sessions,
            ["del", "clone"],
        )

        data += """
           </form>
          </body>
         </html>
        """

        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)


class PagesKV(Pages):
    need_auth = True

    def __init__(self, data):
        self.data = data

    def handle(self, handler):
        if handler.command == "POST":
            form = handler.get_formdata()
            action = form[b"a"][0].decode("utf8")

            if action == "add":
                k = form[b"key"][0].decode("utf8")
                v = form[b"val"][0].decode("utf8")
                self.data[k] = v
            elif action.startswith("del/"):
                _, action_id = action.split("/")
                del self.data[action_id]
            # elif action == "edit":
            #     self.data[action_id] = form[b"val"][0].decode("utf8")
            else:
                handler.send_error(HTTPStatus.BAD_REQUEST)
                return

        data = []
        data += Widget.head("KV")
        data += "<body>"
        data += Widget.navbar()
        data += """
         <form method="post">
          <input type="text" name="key" autofocus>
          <input type="text" name="val">
          <button name="a" value="add">add</button>
        """

        data += Widget.show_dict(
            self.data,
            ["del"],
        )

        data += """
           </form>
          </body>
         </html>
        """

        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)


class PagesQuery(Pages):
    def __init__(self, data):
        self.queries = data

    def handle(self, handler):
        if handler.command == "POST":
            form = handler.get_formdata()

            if b"q" in form:
                query = form[b"q"][0].decode("utf8")

                # FIXME: better id
                _id = _encoded_uuid()
                self.queries[_id] = {
                    "q": query,
                    "a": None,
                    "h": handler.headers["Host"],
                    "t": time.time(),
                }
                handler.send_header("Location", f"{handler.path}/{_id}")
                handler.send_page(HTTPStatus.CREATED, str(_id))
                return

            if b"a" in form:
                if not handler.session.has_auth:
                    handler.send_error(HTTPStatus.UNAUTHORIZED)
                    return

                action = form[b"a"][0].decode("utf8")
                cmd, action_id = action.split("/")

                if cmd == "del":
                    del self.queries[action_id]
                elif cmd == "allow":
                    self.queries[action_id]["a"] = True
                elif cmd == "deny":
                    self.queries[action_id]["a"] = False
                # Edit
                else:
                    handler.send_error(HTTPStatus.BAD_REQUEST)
                    return

        data = []
        data += Widget.head("Queries")
        data += "<body>"
        data += Widget.navbar()
        data += """
         <form method="post">
          <input type="text" name="q" autofocus>
          <button name="qq" value="query">query</button>
         </form>
        """

        if handler.session.has_auth:
            data += """
             <form method="post">
            """

            data += Widget.show_dict(
                self.queries,
                ["allow", "deny", "del"],
            )

            data += "</form>"

        data += """
          </body>
         </html>
        """

        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)


class PagesQueryAnswer(Pages):
    def __init__(self, data, kv):
        self.queries = data
        self.kv = kv

    def handle(self, handler):
        # TODO: hardcodes how deep the subtree is
        _, q, _id = handler.path.split("/")

        try:
            query = self.queries[_id]
        except KeyError:
            handler.send_error(HTTPStatus.NOT_FOUND)
            return

        try:
            allowed = query["a"]
        except KeyError:
            allowed = False

        if not allowed:
            handler.send_error(HTTPStatus.NOT_FOUND)
            return

        try:
            answer = self.kv[query["q"]]
        except KeyError:
            handler.send_error(HTTPStatus.NOT_FOUND)
            return

        handler.send_page(HTTPStatus.OK, answer)


class PagesChat(Pages):
    need_auth = True

    def __init__(self, chat_data):
        self.chat = chat_data

    def handle(self, handler):
        if handler.command == "POST":
            form = handler.get_formdata()
            chat = form[b"chat"][0].decode("utf8")
            note = handler.session.user + ":" + chat
            self.chat.append(note)

        data = []
        data += Widget.head("Chat")
        data += "<body>"
        data += Widget.navbar()
        data += "<table>"

        for i in self.chat:
            data += f"""
             <tr><td>{i}
            """

        data += """
         <tr>
          <td>
           <form method="post">
            <input type="text" id="chat" name="chat" autofocus>
            <input type="submit" value="Submit">
           </form>
         </table>
        """

        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)


class SimpleSite(BetterHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _check_uuid(self):
        """Ensure that every visitor gets a unique identifier"""
        if self.get_cookie("uuid") is not None:
            return

        cookie = _encoded_uuid()

        attribs = {
            "Expires": "Mon, 1-Jan-2035 00:00:00 GMT",
            "HttpOnly": None,
            "Max-Age": 315360000,
            "SameSite": "Lax",
            "Path": "/",
        }

        if self.config.cookie_domain:
            attribs["Domain"] = self.config.cookie_domain

        self.send_cookie("uuid", cookie, **attribs)

    def do_GET(self):
        self._check_uuid()
        self._route2render()

    def do_POST(self):
        self._check_uuid()
        self._route2render()


class SimpleSiteConfig:
    def __init__(self):
        self.cookie_domain = None
        self.auth = None
        self.routes = {}
        self.routes_subtree = {}


def argparser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "-d", "--debug",
        action="store_true",
    )
    ap.add_argument(
        "--cookie_domain",
        help="What cookie domain to use for uuid",
    )
    ap.add_argument(
        "port",
        action="store",
        default=8080,
        type=int,
        nargs="?",
        help="Serve requests on TCP port (default 8080)"
    )

    args = ap.parse_args()
    return args


def main():
    args = argparser()

    data_chat = []
    data_kv = {}
    data_query = {}

    style = """
        table.w {
         border-collapse: collapse;
        }
        td.w {
         border-style: solid;
         border-width: 1px;
        }
    """

    config = SimpleSiteConfig()
    config.cookie_domain = args.cookie_domain
    config.auth = Authenticator()
    config.routes = {
        "/auth/login": PagesLogin(),
        "/auth/list": PagesAuthList(),
        "/kv": PagesKV(data_kv),
        "/q": PagesQuery(data_query),
        "/sitemap": PagesMap(),
        "/test/notes": PagesChat(data_chat),
        "/test/page": PagesStatic("A Testable Page"),
        "/style.css": PagesStatic(style, content_type="text/css"),
    }
    config.routes_subtree = {
        "/q/": PagesQueryAnswer(data_query, data_kv),
    }

    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(SimpleSite, config)

    httpd = socketserver.TCPServer(("", args.port), handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return


if __name__ == '__main__':
    main()
