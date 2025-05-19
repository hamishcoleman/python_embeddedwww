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
import urllib.parse
import uuid

from http import HTTPStatus
from types import MappingProxyType


class Session:
    def __init__(self):
        self.id = None
        self.data = None
        self.state = None

    @property
    def user(self):
        return self.data["user"]

    @property
    def has_auth(self):
        return self.state == "login"


class Authenticator:
    def __init__(self):
        self.sessions = {}
        # TODO: param to load auth table

    def _get_user_db(self, user, password):
        # TODO:
        # - lookup user/password in auth table
        # - construct data from auth table details
        if user != "test":
            return None
        if password != "1234":
            return None

        # We enforce that the session data is readonly as that will allow
        # the use of JWT (or similar) to populate the session data
        data = MappingProxyType({
            "user": user,
            "admin": True,
        })
        return data

    def end_session(self, session):
        if session is None:
            return
        del self.sessions[session.id]
        session.state = "logout"

    def request2session(self, request):
        session = Session()
        session.id = request.get_cookie("sessionid")
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

        rnd = uuid.uuid4().bytes
        session.id = base64.urlsafe_b64encode(rnd).strip(b"=").decode("utf8")
        session.data = data

        # Persist the session in the browser
        response.send_cookie(
            "sessionid",
            session.id,
            SameSite="Lax",
            Path="/",
        )
        self.sessions[session.id] = session.data

        return session


class Pages:
    pass


class PagesError(Pages):
    need_auth = False

    @classmethod
    def generic(cls, code):
        self = cls()
        self.code = code
        return self

    def handle(self, server, session):
        # TODO:
        # - message, explain
        server.send_error(self.code)


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

    def get_request_handler(self):
        try:
            handler = handlers[self.path]
        except KeyError:
            return PagesError.generic(HTTPStatus.NOT_FOUND), None

        # TODO: could add handler.need_session and avoid getting session
        session = self.config.auth.request2session(self)
        if handler.need_auth:
            if not session.has_auth:
                return PagesError.generic(HTTPStatus.UNAUTHORIZED), None

        return handler, session


class PagesTest(Pages):
    need_auth = False

    def handle(self, server, session):
        server.send_response(HTTPStatus.OK)
        server.send_header('Content-type', "text/html")
        server.end_headers()
        server.wfile.write(b"A Testable Page")


class PagesMap(Pages):
    need_auth = False

    def handle(self, server, session):
        data = """<!DOCTYPE html>
         <html>
         <head>
          <title>Index</title>
         </head>
         <body>
         <ul>
        """

        for path, handler in sorted(handlers.items()):
            if not handler.need_auth or session.has_auth:
                data += f"""
                 <li><a href="{path}">{path}</a>
                """

        data += """
         </ul>
         </body>
         </html>
        """

        server.send_response(HTTPStatus.OK)
        server.send_header("Content-type", "text/html; charset=utf-8")
        server.end_headers()
        server.wfile.write(data.encode("utf8"))


class PagesLogin(Pages):
    need_auth = False

    def handle(self, server, session):
        if server.command == "POST":
            form = server.get_formdata()
            action = form[b"a"][0].decode("utf8")

            if action == "login":
                user = form[b"user"][0].decode("utf8")
                password = form[b"pass"][0].decode("utf8")
                session = server.config.auth.login2session(
                    server,
                    user,
                    password
                )

                # Make reloading nicer
                # TODO: hardcodes the location of this page
                server.send_header("Location", "login")
                server.send_error(HTTPStatus.SEE_OTHER)
                return
            else:
                try:
                    server.config.auth.end_session(session)
                except KeyError:
                    session.state = "bad"

        data = b"""<!DOCTYPE html>
          <html>
          <head>
           <title>Login</title>
          </head>
          <body>
           <form method="post">
            <table>
        """

        data += f"""
          <tr>
           <th align=right>Client:
           <td>{server.client_address}
        """.encode("utf8")

        # TODO:
        # - if we are behind a proxy, use the header instead of the
        #   client_address

        # TODO:
        # if server.client_address[0] == "127.0.0.1":
        #     data += pid/processname/args

        host = server.headers["Host"]
        data += f"""
          <tr>
           <th align=right>Host:
           <td>{host}
        """.encode("utf8")

        cookie_uuid = server.get_cookie("uuid")
        if cookie_uuid:
            data += f"""
            <tr>
             <th align=right>UUID:
             <td>{cookie_uuid}
            """.encode("utf8")

        if session.has_auth:
            data += f"""
            <tr>
            <tr>
             <th align=right><label for="user">Username:</label>
             <td>{session.user}
            <tr>
            <tr>
             <th>
             <td align=right><button name="a" value="logout">Logout</button>
            """.encode("utf8")
        else:
            data += b"""
            <tr>
            <tr>
             <th align=right><label for="user">Username:</label>
             <td><input type="text" id="user" name="user">
            <tr>
             <th align=right><label for="pass">Password:</label>
             <td><input type="password" id="pass" name="pass">
            <tr>
             <th>
             <td align=right><button name="a" value="login">Login</button>
            """

        if session.state == "bad":
            data += b"""
            <tr>
             <th>
             <td>Bad Attempt
            """
            code = HTTPStatus.UNAUTHORIZED
        else:
            code = HTTPStatus.OK

        data += b"""
           </table>
          </form>
          </body>
        """

        server.send_response(code)
        server.send_header('Content-type', "text/html; charset=utf-8")
        server.end_headers()
        server.wfile.write(data)


class PagesAuthList(Pages):
    need_auth = True

    def handle(self, server, session):
        if not session.data.get("admin", False):
            server.send_error(HTTPStatus.UNAUTHORIZED)
            return

        if server.command == "POST":
            form = server.get_formdata()
            action = form[b"a"][0].decode("utf8")

            action, action_id = action.split("/")

            if action == "del":
                action_session = Session()
                action_session.id = action_id
                server.config.auth.end_session(action_session)
            else:
                server.send_error(HTTPStatus.BAD_REQUEST)
                return

        data = """<!DOCTYPE html>
          <html>
          <head>
           <title>Sessions</title>
          </head>
          <body>
           <form method="post">
            <table>
             <tr>
              <th>ID
              <th>Data
              <th>Action
        """

        for k, v in server.config.auth.sessions.items():
            data += f"""
             <tr>
              <td>{k}
              <td>{v}
              <td>
               <button name="a" value="del/{k}">Del</button>
            """

        data += """
            </table>
           </form>
          </body>
         </html>
        """

        server.send_response(HTTPStatus.OK)
        server.send_header('Content-type', "text/html; charset=utf-8")
        server.end_headers()
        server.wfile.write(data.encode("utf8"))


class PagesChat(Pages):
    need_auth = True

    def __init__(self):
        self.chat = []

    def handle(self, server, session):
        if server.command == "POST":
            form = server.get_formdata()
            chat = form[b"chat"][0].decode("utf8")
            note = session.user + ":" + chat
            self.chat.append(note)

        data = """<!DOCTYPE html>
          <html>
          <head>
           <title>Chat</title>
          </head>
          <body>
          <table>
        """

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

        server.send_response(HTTPStatus.OK)
        server.send_header('Content-type', "text/html; charset=utf-8")
        server.end_headers()
        server.wfile.write(data.encode("utf8"))


# FIXME: global
handlers = {
    "/auth/login": PagesLogin(),
    "/auth/list": PagesAuthList(),
    "/chat/1": PagesChat(),
    "/chat/2": PagesChat(),
    "/sitemap": PagesMap(),
    "/test": PagesTest(),
}


class SimpleSite(BetterHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _check_uuid(self):
        """Ensure that every visitor gets a unique identifier"""
        if self.get_cookie("uuid") is not None:
            return

        random = uuid.uuid4().bytes
        cookie = base64.urlsafe_b64encode(random).strip(b"=").decode("utf8")

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

    def handle_request(self):
        self._check_uuid()
        handler, session = self.get_request_handler()
        handler.handle(self, session)

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()


class SimpleSiteConfig:
    def __init__(self):
        self.cookie_domain = None
        self.auth = None


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

    config = SimpleSiteConfig()
    config.cookie_domain = args.cookie_domain
    config.auth = Authenticator()

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
