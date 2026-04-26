"""
Display jdoc objects

(Currently jdoc are just json, but they will grow in context)
"""

import os

from .. import Pages

from http import HTTPStatus


def add_routes(routes):
    routes["/static/dragable.css"] = Pages.StaticFile(
        os.path.join(os.path.dirname(__file__), "dragable.css"),
        content_type="text/css; charset=utf-8",
    )
    routes["/static/dragable.js"] = Pages.StaticFile(
        os.path.join(os.path.dirname(__file__), "dragable.js"),
        content_type="application/javascript; charset=utf-8",
    )


def add_routes_subtree(routes_subtree, table):
    """Add our default set of pages at their usual paths"""
    routes_subtree["/jdoc/"] = JdocDetail(table)


class TableDragable:
    def __init__(self):
        self.style = "dragable"

    def __str__(self):
        r = []
        r += [f'<table class="{self.style}">\n']
        r += ["""
          <thead>
           <tr>
            <th>Key
            <th>Val
          <tbody>
        """]


class JdocCategory:
    def __init__(self):
        self.field_order = []
        self.field_order_hidden = []
        self.actions = []


class Jdoc:
    def __init__(self, data, category):
        self.data = data
        self.category = category
        # self.timestamps


class JdocDetail(Pages.SimpleForm):
    need_auth = True

    def __init__(self, table):
        super().__init__()
        self.table = table

        # Fake up a category until we build out
        self.category = JdocCategory()
        self.category.field_order = [
            "fqdn",
            "pub_key_ed25519",
            "instance_id",
        ]
        self.category.field_order_hidden = [
            "hostname",
        ]

    def _jdoc_get(self, _id):
        data = self.table[_id]
        # Presumably, eventually the self.table will be returning a Jdoc, but
        # for now, we build it here
        return Jdoc(data, self.category)

    def _notfound(self, handler):
        """while debugging, output some useful info when _id not found"""
        # handler.send_error(HTTPStatus.NOT_FOUND)
        data = []
        head = handler.config.Widget.head("notfound")
        data += [head]
        data += ["<body>"]
        data += ["<ul>"]
        for k in self.table.keys():
            data += [f'<li><a href="/jdoc/{k}">{k}</a>']
        handler.send_page(HTTPStatus.OK, data)

    def do_GET(self, handler):
        # TODO: hardcodes how deep the subtree is
        _, path, _id = handler.path.split("/")

        try:
            jdoc = self._jdoc_get(_id)
        except KeyError:
            self._notfound(handler)
            return

        data = []
        head = handler.config.Widget.head("JdocDetail")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()

        # TODO: jdoc sort order

        table = handler.config.Widget.table()
        table.style = "dragable"
        table.data = jdoc.data
        table.columns = {
            # TODO: drag handle with hover timestamp
            None: "Key",
            "Val": None,
        }
        # TODO: action edit val
        table.update_head(head)
        data += [table]

        # TODO: table of actions
        # TODO: collapsed div containing the hidden fields
        # TODO: save current order

        data += ["""
          </body>
         </html>
        """]

        handler.send_page(HTTPStatus.OK, data)
