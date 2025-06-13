#!/usr/bin/env python3
"""Simple http website to receive cloud init phone home data"""
#

import argparse
import functools
import os
import signal
import socketserver
import sys

from http import HTTPStatus


# Ensure that we look for any modules in our local lib dir.  This allows simple
# testing and development use.  It also does not break the case where the lib
# has been installed properly on the normal sys.path
sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'python3'),
)


import hc.http.WebSite  # noqa: E402


def argparser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "-d", "--debug",
        action="store_true",
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


class PagesPhoneHome(hc.http.WebSite.Pages):
    def __init__(self, data):
        self.data = data
        super().__init__()

    def do_POST(self, handler):
        form = handler.get_formdata()

        if b"a" in form:
            if not handler.session.has_auth:
                handler.send_error(HTTPStatus.UNAUTHORIZED)
                return

            action = form[b"a"][0].decode("utf8")
            cmd, action_id = action.split("/")

            if cmd == "del":
                del self.data[action_id]
            else:
                handler.send_error(HTTPStatus.BAD_REQUEST)
                return

            # Make refreshing nicer
            handler.send_header("Location", handler.path)
            handler.send_error(HTTPStatus.SEE_OTHER)
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

        key = item["instance_id"]
        self.data[key] = item

        handler.send_page(HTTPStatus.OK, "Recorded")

    def do_GET(self, handler):
        data = []
        data += handler.config.Widget.head("Phone Home")
        data += ["<body>"]
        data += handler.config.Widget.navbar()

        if not handler.session.has_auth:
            handler.send_error(HTTPStatus.UNAUTHORIZED)
            return

        data += ["""
         <form method="post">
        """]

        data += handler.config.Widget.show_dict(
            self.data,
            ["del"],
        )

        data += ["</form>"]

        data += ["""
          </body>
         </html>
        """]

        data = "".join(data)
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

    config = hc.http.WebSite.Config()
    config.auth = hc.http.WebSite.AuthenticatorTest()
    config.routes = {
        "/auth/login": hc.http.WebSite.PagesLogin(),
        "/auth/list": hc.http.WebSite.PagesAuthList(),
        "/metrics": hc.http.WebSite.PagesMetrics(),
        "/sitemap": hc.http.WebSite.PagesMap(),
        "/style.css": hc.http.WebSite.PagesStatic(
            style,
            content_type="text/css",
        ),

        "/phone_home": PagesPhoneHome(data),
    }

    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(RequestHandler, config)

    httpd = socketserver.TCPServer(("", args.port), handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return


if __name__ == '__main__':
    main()
