"""
Show an index to the pages on the site
"""

import hc.http.Pages

from . import auth
from http import HTTPStatus


def add_routes(routes):
    """Add the default sitemap page with its usual path"""
    routes["/sitemap"] = SiteMap()


class SiteMap(hc.http.Pages.Base):
    def do_GET(self, handler):
        data = []
        head = handler.config.Widget.head("Index")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()
        data += ["<ul>"]

        for path, page in sorted(handler.config.routes.items()):
            if not auth.check_aaa(handler.session, page):
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
