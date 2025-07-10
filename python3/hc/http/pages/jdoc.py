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

    def do_GET(self, handler):
        # TODO: hardcodes how deep the subtree is
        _, path, _id = handler.path.split("/")

        try:
            jdoc = self.table[_id]
        except KeyError:
            # handler.send_error(HTTPStatus.NOT_FOUND)
            data = []
            data += ["_id:", _id, "\n"]
            data += [list(self.table.keys())]
            handler.send_page(HTTPStatus.OK, data)
            return

        # TODO: jdoc sort order

        data = []
        head = handler.config.Widget.head("JdocDetail")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()

        table = handler.config.Widget.table()
        table.style = "sortable"
        table.data = jdoc
        table.columns = {
            # TODO: drag handle with hover timestamp
            None: "Key",
            "Val": None,
        }
        table.update_head(head)
        data += [table]

        # TODO: table of actions
        # TODO: collapsed div containing the hidden fields

        data += ["""
          </body>
         </html>
        """]

        handler.send_page(HTTPStatus.OK, data)
