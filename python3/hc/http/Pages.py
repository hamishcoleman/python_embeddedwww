"""
Provide useful implementations for some simple pages.
"""

import hc.http.Auth
import shutil
import urllib

from http import HTTPStatus


class Base:
    """The base Page handler class.  This is subclassed to build pages"""
    need_auth = False
    need_admin = False

    def __init__(self):
        self.request = 0
        self.elapsed = float()
        self.tbf = hc.http.TBF.Filter(1, 10)


class Metrics(Base):
    def do_GET(self, handler):
        d = []
        for route, page in handler.config.routes.items():
            d += [f'site_request_count{{route="{route}"}} {page.request}\n']
            d += [f'site_request_seconds{{route="{route}"}} {page.elapsed}\n']

        for route, page in handler.config.routes_subtree.items():
            d += [f'site_request_count{{route="{route}"}} {page.request}\n']
            d += [f'site_request_seconds{{route="{route}"}} {page.elapsed}\n']

        handler.send_page(HTTPStatus.OK, d, content_type="text/plain")


class Static(Base):
    def __init__(self, body, content_type="text/html; charset=utf-8"):
        self.body = body
        self.content_type = content_type
        super().__init__()

    def do_GET(self, handler):
        handler.send_page(
            HTTPStatus.OK,
            self.body,
            content_type=self.content_type,
        )


class StaticFile(Base):
    def __init__(self, filename, content_type="text/html; charset=utf-8"):
        self.filename = filename
        self.content_type = content_type
        super().__init__()

    def do_GET(self, handler):
        # TODO: there are a lot of useful bits in
        # http.server.SimpleHTTPRequestHandler.send_head()
        with open(self.filename, "rb") as f:
            handler.send_response(HTTPStatus.OK)
            handler.send_header("Content-type", self.content_type)
            handler.end_headers()
            shutil.copyfileobj(f, handler.wfile)


class KV(Base):
    need_auth = True

    def __init__(self, data):
        self.data = data
        super().__init__()

    def do_POST(self, handler):
        form = handler.get_formdata()
        action = form[b"a"][0].decode("utf8")

        if action == "add":
            try:
                k = form[b"key"][0].decode("utf8")
                v = form[b"val"][0].decode("utf8")
                self.data[k] = v
            except KeyError:
                pass
        elif action.startswith("del/"):
            _, action_id = action.split("/")
            del self.data[action_id]
        elif action.startswith("edit/"):
            _, action_id = action.split("/")
            action_id = urllib.parse.quote(action_id)
            handler.send_header("Location", f"{handler.path}/{action_id}")
            handler.send_error(HTTPStatus.SEE_OTHER)
            return
        else:
            handler.send_error(HTTPStatus.BAD_REQUEST)
            return

        # TODO: refactor to never chain
        return self.do_GET(handler)

    def do_GET(self, handler):
        data = []
        head = handler.config.Widget.head("KV")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()
        data += ["""
         <form method="post">
          <input type="text" name="key" placeholder="key" autofocus>
          <input type="text" name="val" placeholder="val">
          <button name="a" value="add">add</button>
         </form>
        """]

        data += ['<form id="action" method="post"></form>']

        table = handler.config.Widget.table()
        table.data = self.data
        table.columns = {
            None: "key",
            "val": None,
        }
        table.actions = ["edit", "del"]
        # Deliberately avoid calling table.update_head() to show that it
        # can still work as a table
        data += [table]

        data += ["""
          </body>
         </html>
        """]

        handler.send_page(HTTPStatus.OK, data)


class KVEdit(Base):
    need_auth = True

    def __init__(self, kv):
        self.kv = kv
        super().__init__()

    def do_POST(self, handler):
        # TODO: hardcodes how deep the subtree is
        _, path, key = handler.path.split("/")

        key = urllib.parse.unquote(key)

        form = handler.get_formdata()
        val = form[b"val"][0].decode("utf8")
        self.kv[key] = val
        handler.send_header("Location", f"/{path}")
        handler.send_error(HTTPStatus.SEE_OTHER)
        return

    def do_GET(self, handler):
        # TODO: hardcodes how deep the subtree is
        _, path, key = handler.path.split("/")

        key = urllib.parse.unquote(key)
        val = self.kv.get(key, "")

        data = []
        head = handler.config.Widget.head("KV Edit")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()
        data += [f"""
          <form method="post">
           <input type="text" name="key" readonly value="{key}">
           <input type="text" name="val" value="{val}" required autofocus>
           <button name="a" value="add">edit</button>
          </form>
         </body>
        </html>
        """]

        handler.send_page(HTTPStatus.OK, data)


class SiteMap(Base):
    def do_GET(self, handler):
        data = []
        head = handler.config.Widget.head("Index")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()
        data += ["<ul>"]

        for path, page in sorted(handler.config.routes.items()):
            if not handler._checkperms(page):
                continue
            data += [f"""
             <li><a href="{path}">{path}</a>
            """]

        data += ["""
         </ul>
         </body>
         </html>
        """]

        handler.send_page(HTTPStatus.OK, data)


class Login(Base):
    def __init__(self):
        super().__init__()
        self.attribs = {}

    def set_attribs(self, handler):
        """Set the info that is shown on the login page.  Overridable"""
        self.attribs["Client"] = handler.client_address
        # TODO:
        # - if we are behind a proxy, use the header instead of the
        #   client_address

        self.attribs["Host"] = handler.headers["Host"]
        self.attribs["Username"] = handler.session.user

    def do_POST(self, handler):
        form = handler.get_formdata()
        action = form[b"a"][0].decode("utf8")

        if action == "logout":
            try:
                handler.config.auth.end_session(
                    handler.session,
                    handler=handler
                )
            except KeyError:
                handler.session.state = "bad"

        if action == "login":
            user = form[b"user"][0].decode("utf8")
            password = form[b"pass"][0].decode("utf8")
            handler.config.auth.login2session(
                handler,
                user,
                password
            )

        # TODO: show something to tell user they have a bad login

        # Make reloading nicer
        handler.send_header("Location", handler.path)
        handler.send_error(HTTPStatus.SEE_OTHER)
        return

    def do_GET(self, handler):
        self.set_attribs(handler)

        data = []
        head = handler.config.Widget.head("Login")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()
        data += ["""
           <form method="post">
            <table>
        """]

        for k, v in self.attribs.items():
            if v is None:
                continue
            data += [f"""
              <tr>
               <th align=right>{k}:
               <td>{v}
            """]

        if handler.session.has_auth:
            data += ["""
            <tr>
            <tr>
             <th>
             <td align=right><button name="a" value="logout">Logout</button>
            """]
        else:
            data += ["""
            <tr>
             <th align=right><label for="user">Username:</label>
             <td><input type="text" id="user" name="user" required autofocus>
            <tr>
             <th align=right><label for="pass">Password:</label>
             <td><input type="password" id="pass" name="pass" required>
            <tr>
             <th>
             <td align=right><button name="a" value="login">Login</button>
            """]

        if handler.session.state == "bad":
            data += ["""
            <tr>
             <th>
             <td>Bad Attempt
            """]
            code = HTTPStatus.UNAUTHORIZED
        else:
            code = HTTPStatus.OK

        data += ["""
           </table>
          </form>
          </body>
        """]

        handler.send_page(code, data)


class AuthList(Base):
    need_auth = True
    need_admin = True

    def do_POST(self, handler):
        form = handler.get_formdata()
        action = form[b"a"][0].decode("utf8")

        action, action_id = action.split("/")
        action_session = hc.http.Auth.Session()
        action_session.id = action_id

        if action == "del":
            handler.config.auth.end_session(action_session)
            handler.send_header("Location", handler.path)
            handler.send_error(HTTPStatus.SEE_OTHER)
            return
        elif action == "clone":
            handler.config.auth.replace_data(action_session, self.session)

            # TODO: hardcodes the location of this page
            handler.send_header("Location", "login")
            handler.send_error(HTTPStatus.SEE_OTHER)
            return
        else:
            handler.send_error(HTTPStatus.BAD_REQUEST)
            return

    def do_GET(self, handler):
        data = []
        head = handler.config.Widget.head("Sessions")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()

        data += ['<form id="action" method="post"></form>']

        table = handler.config.Widget.table()
        table.caption = "Sessions List"
        table.data = handler.config.auth.sessions
        table.columns = {
            "createdat": None,
            "user": None,
            "admin": None,
        }
        table.actions = ["del", "clone"]
        # Deliberately avoid calling table.update_head() to show that it
        # can still work as a table
        data += [table]

        data += ["""
          </body>
         </html>
        """]

        handler.send_page(HTTPStatus.OK, data)
