#!/usr/bin/env python3
"""Simple http website to receive cloud init phone home data"""
#

import argparse
import functools
import os
import signal
import socketserver
import sys
import yaml

from http import HTTPStatus


# Ensure that we look for any modules in our local lib dir.  This allows simple
# testing and development use.  It also does not break the case where the lib
# has been installed properly on the normal sys.path
sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'python3'),
)


import hc.http.Auth     # noqa: E402
import hc.http.Pages    # noqa: E402
import hc.http.WebSite  # noqa: E402
import hc.http.pages    # noqa: E402
import hc.http.pages.jdoc  # noqa: E402


def argparser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "-d", "--debug",
        action="store_true",
    )
    ap.add_argument(
        "--config",
        help="Location of config file",
    )
    ap.add_argument(
        "--db",
        help="Location of database",
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


class PagesPhoneHome(hc.http.Pages.SimpleForm):
    def __init__(self, data):
        self.data = data
        super().__init__()

    def form_del(self, handler, form):
        row = form[b"_row"][0].decode("utf8")
        del self.data[row]
        handler.send_location()

    def do_POST(self, handler):
        form = handler.form

        if b"_action" in form:
            if not handler.session.has_auth:
                handler.send_error(HTTPStatus.UNAUTHORIZED)
                return

            super().do_POST(handler)
            return

        if len(self.data) > 100:
            # prevent a memory exhaustion attack
            handler.send_error(HTTPStatus.BAD_REQUEST)
            return

        item = {}
        for k, v in form.items():
            k = k.decode("utf8")
            if len(v) == 1:
                v = v[0]
                v = v.decode("utf8")
            item[k] = v

        item["_ctime"] = handler.time_start
        key = item["instance_id"]
        self.data[key] = item

        handler.send_page(HTTPStatus.OK, "Recorded")

    def do_GET(self, handler):
        if not handler.session.has_auth:
            handler.send_error(HTTPStatus.UNAUTHORIZED)
            return

        data = []
        head = handler.config.Widget.head("Phone Home")
        head.stylesheets.add("/style.css")
        # TODO: this harcodes the location of the javascript
        data += [head]

        data += handler.config.Widget.navbar()

        table = handler.config.Widget.table()
        table.style = "sortable"
        table.caption = "A Caption"
        table.data = self.data
        table.columns = {
            "_ctime": "Created",
            "instance_id": "ID",
            "hostname": None,
            "fqdn": None,
            "pub_key_ed25519": "Pub Key",
            "Action": None,
        }
        table.action_column = "Action"
        table.actions = ["del"]
        table.update_head(head)
        data += [table]

        data += ["""
          </body>
         </html>
        """]

        handler.send_page(HTTPStatus.OK, data)


# TODO:
# subtree with raw json data for a data entry


class RequestHandler(hc.http.WebSite.RequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.render_page()

    def do_POST(self):
        self.render_page()


def main():
    args = argparser()

    if args.config:
        with open(args.config) as f:
            config = yaml.safe_load(f)
    else:
        config = {}

    data = {}

    style = """
        table.w {
         border-collapse: collapse;
        }
        td.w {
         border-style: solid;
         border-width: 1px;
        }
    """

    webconfig = hc.http.WebSite.Config()
    if args.db:
        webconfig.auth = hc.http.Auth.Sqlite(args.db)
    elif "users" in config:
        webconfig.auth = hc.http.Auth.RAMData(config["users"])
    else:
        webconfig.auth = hc.http.Auth.Test()

    if "jwtsecret" in config:
        webconfig.auth.secret = config["jwtsecret"].encode("ascii")

    hc.http.pages.add_routes(webconfig.routes)
    webconfig.routes.update({
        "/style.css": hc.http.Pages.Static(
            style,
            content_type="text/css; charset=utf-8",
        ),
        "/static/sortable.js": hc.http.Pages.StaticFile(
            "static/sortable.js",
            content_type="application/javascript; charset=utf-8",
        ),
        "/static/sortable.css": hc.http.Pages.StaticFile(
            "static/sortable.css",
            content_type="text/css; charset=utf-8",
        ),

        "/phone_home": PagesPhoneHome(data),
    })

    hc.http.pages.jdoc.add_routes_subtree(webconfig.routes_subtree, data)

    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(RequestHandler, webconfig)

    httpd = socketserver.TCPServer(("", args.port), handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return


if __name__ == '__main__':
    main()
