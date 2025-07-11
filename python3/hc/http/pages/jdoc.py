"""
Display jdoc objects

(Currently jdoc are just json, but they will grow in context)
"""

from .. import Pages

from http import HTTPStatus


def add_routes_subtree(routes_subtree, table):
    """Add our default set of pages at their usual paths"""
    routes_subtree["/jdoc/"] = JdocDetail(table)


class JdocDetail(Pages.SimpleForm):
    need_auth = True

    def __init__(self, table):
        super().__init__()
        self.table = table

    def _jdoc_get(self, _id):
        return self.table[_id]

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
        table.data = jdoc
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
