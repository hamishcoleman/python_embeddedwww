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


class Session:
    def __init__(self):
        self.id = None
        self.data = None
        self.state = "logout"

    @property
    def user(self):
        return self.data["user"]


class Authenticator:
    def __init__(self):
        self.sessions = {}
        # TODO: param to load auth table

    def _check_login(self, user, password):
        # TODO:
        # - lookup user/password in auth table
        if user != "test":
            return False
        if password != "1234":
            return False

        return True

    def end_session(self, sessionid):
        del self.sessions[sessionid]

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
        if not self._check_login(user, password):
            session.state = "bad"
            return session
        session.state = "login"

        rnd = uuid.uuid4().bytes
        session.id = base64.urlsafe_b64encode(rnd).strip(b"=").decode("utf8")
        session.data = {
            "user": user,
        }

        # Persist the session
        response.send_cookie("sessionid", session.id, SameSite="Lax")
        self.sessions[session.id] = session.data

        return session


class BetterHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
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


class SimpleSite(BetterHTTPRequestHandler):

    def __init__(self, config, *args, **kwargs):
        # save the config object
        self.config = config
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
        }

        if self.config.cookie_domain:
            attribs["Domain"] = self.config.cookie_domain

        self.send_cookie("uuid", cookie, **attribs)

    def do_path_login(self):
        if self.command == "POST":
            form = self.get_formdata()
            user = form[b"user"][0].decode("utf8")
            password = form[b"pass"][0].decode("utf8")
            session = self.config.auth.login2session(self, user, password)
        else:
            session = self.config.auth.request2session(self)

        data = b""
        data += b"""<!DOCTYPE html>
          <html>
          <head>
           <title>Login</title>
          </head>
          <body>
        """

        if session.state == "login":
            data += b"""
             <form method="post" action="login/logout">
             <table>
            """
        else:
            data += b"""
             <form method="post">
             <table>
            """

        data += f"""
          <tr>
           <th align=right>Client:
           <td>{self.client_address}
        """.encode("utf8")

        # TODO:
        # - if we are behind a proxy, use the header instead of the
        #   client_address

        # TODO:
        # if self.client_address[0] == "127.0.0.1":
        #     data += pid/processname/args

        host = self.headers["Host"]
        data += f"""
          <tr>
           <th align=right>Host:
           <td>{host}
        """.encode("utf8")

        cookie_uuid = self.get_cookie("uuid")
        if cookie_uuid:
            data += f"""
            <tr>
             <th align=right>UUID:
             <td>{cookie_uuid}
            """.encode("utf8")

        if session.state == "login":
            data += f"""
            <tr>
            <tr>
             <th align=right><label for="user">Username:</label>
             <td>{session.user}
            <tr>
            <tr>
             <th>
             <td align=right><input type="submit" value="Logout">
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
             <td align=right><input type="submit" value="Login">
            """

        if session.state == "bad":
            data += b"""
            <tr>
             <th>
             <td>Bad Login Attempt
            """

        data += b"""
           </table>
          </form>
          </body>
        """

        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(data)

    def do_path_logout(self):
        if self.command != "POST":
            # TODO: send a message "action not acceptable"
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)

        session = self.config.auth.request2session(self)

        try:
            self.config.auth.end_session(session.id)
            session.state = "logout"
        except KeyError:
            session.state = "bad"

        data = b""
        data += b"""<!DOCTYPE html>
          <html>
          <head>
           <title>Logout</title>
          </head>
          <body>
           <table>
        """

        if session.state == "logout":
            data += b"""
            <tr>
             <th align=right>Logged out
            <tr>
            <tr>
             <th>
             <td align=right><a href="/login">Login</a>
            """

        if session.state == "bad":
            data += b"""
            <tr>
             <th>
             <td>Bad Login Attempt
            """

        data += b"""
           </table>
          </form>
          </body>
        """

        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(data)

    def do_path_test(self):
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', "text/html")
        self.end_headers()
        self.wfile.write(b"A Testable Page")

    def get_request_handler(self):
        handlers = {
            "/login": self.do_path_login,
            "/login/logout": self.do_path_logout,
            "/test": self.do_path_test,
        }

        try:
            handler = handlers[self.path]
        except KeyError:
            handler = None

        return handler

    def do_GET(self):
        self._check_uuid()

        handler = self.get_request_handler()
        if handler is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        handler()
        return

    def do_POST(self):
        self._check_uuid()

        handler = self.get_request_handler()
        if handler is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        handler()


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
