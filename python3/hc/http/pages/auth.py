"""
A collection of standard page objects.
All related to authentication
"""

import hc.http.Pages

from http import HTTPStatus


def add_routes(routes):
    """Add the default auth pages with their usual paths"""
    routes["/auth/login"] = Login()
    routes["/auth/logout"] = Logout()
    routes["/auth/list"] = List()
    routes["/auth/check"] = Check()


def check_aaa(session, page):
    """Check the Page attrs against the request session"""

    if page.need_auth:
        if not session.has_auth:
            return False
    if page.need_admin:
        if not session.has_admin:
            return False
    return True


class Login(hc.http.Pages.SimpleForm):
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

    def form_logout(self, handler, form):
        handler.config.auth.end_session(handler.session, handler=handler)
        handler.send_location()

    def form_login(self, handler, form):
        user = form[b"user"][0].decode("utf8")
        password = form[b"pass"][0].decode("utf8")
        handler.config.auth.login2session(handler, user, password)
        handler.send_location()

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
             <td align=right>
              <button name="_action" value="logout">Logout</button>
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
             <td align=right>
              <button name="_action" value="login">Login</button>
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


class Logout(hc.http.Pages.Base):
    need_auth = True

    def do_GET(self, handler):
        handler.config.auth.end_session(handler.session, handler=handler)
        handler.send_location("/auth/login")
        # TODO: hardcodes the location of login


class List(hc.http.Pages.SimpleForm):
    need_auth = True
    need_admin = True

    def form_del(self, handler, form):
        row = form[b"_row"][0].decode("utf8")
        action_session = hc.http.Auth.Session()
        action_session.id = row
        handler.config.auth.end_session(action_session, handler=handler)

        handler.send_location()

    def form_clone(self, handler, form):
        row = form[b"_row"][0].decode("utf8")
        action_session = hc.http.Auth.Session()
        action_session.id = row
        handler.config.auth.replace_data(action_session, handler.session)

        # TODO: hardcodes the location of the login page
        handler.send_location("login")

    def do_GET(self, handler):
        data = []
        head = handler.config.Widget.head("Sessions")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()

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


class Check(hc.http.Pages.Base):
    """Provides a page that will check the client auth and return status"""
    need_auth = True

    def do_GET(self, handler):
        handler.send_page(HTTPStatus.OK, "OK")
