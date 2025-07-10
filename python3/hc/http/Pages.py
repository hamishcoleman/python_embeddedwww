"""
Provide useful implementations for some simple pages.
"""

import hc.http.Auth
import hc.http.TBF
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


class SimpleForm(Base):
    def do_POST(self, handler):
        form = handler.form
        action = form[b"_action"][0].decode("utf8")

        action_method_name = 'form_' + action
        if not hasattr(self, action_method_name):
            handler.send_error(HTTPStatus.NOT_IMPLEMENTED)
            return
        action_handler = getattr(self, action_method_name)
        action_handler(handler, form)


class KV(SimpleForm):
    need_auth = True

    def __init__(self, data):
        self.data = data
        super().__init__()

    def form_add(self, handler, form):
        k = form[b"key"][0].decode("utf8")
        v = form[b"val"][0].decode("utf8")
        self.data[k] = v

        handler.send_location()

    def form_del(self, handler, form):
        row = form[b"_row"][0].decode("utf8")
        del self.data[row]

        handler.send_location()

    def form_edit(self, handler, form):
        row = form[b"_row"][0].decode("utf8")
        row = urllib.parse.quote(row)
        handler.send_location(f"{handler.path}/{row}")

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
          <button name="_action" value="add">add</button>
         </form>
        """]

        table = handler.config.Widget.table()
        table.data = self.data
        table.columns = {
            None: "key",
            "val": None,
            "Action": None,
        }
        table.action_column = "Action"
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

        form = handler.form
        val = form[b"val"][0].decode("utf8")
        self.kv[key] = val
        handler.send_location(f"/{path}")

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
