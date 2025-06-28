"""
Provide useful implementations for some simple pages.
"""

import hc.http.WebSite
import urllib

from http import HTTPStatus


class KV(hc.http.WebSite.Pages):
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


class KVEdit(hc.http.WebSite.Pages):
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
