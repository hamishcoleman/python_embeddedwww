#!/usr/bin/env python3
"""Simple http website providing some session helper services"""
#
# TODO:
# - HTTP/1.1, requires content length
# - ratelimit uuid generation

import argparse
import functools
import os
import signal
import socketserver
import subprocess
import sys
import urllib.parse

from http import HTTPStatus


# Ensure that we look for any modules in our local lib dir.  This allows simple
# testing and development use.  It also does not break the case where the lib
# has been installed properly on the normal sys.path
sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'python3'),
)


import hc.http.Auth  # noqa: E402
import hc.http.Pages  # noqa: E402
import hc.http.WebSite  # noqa: E402


def _tuple2pid(server, client):
    # TODO:
    # - confirm server and client are localhost

    text = subprocess.getoutput(
        f"ss -H -n -p -t 'dport = :{server[1]} and sport = :{client[1]}'",
    )
    try:
        process_text = text.split()[5]
        # users:(("curl",pid=1274227,fd=5))
    except IndexError:
        return None

    # TODO: there could be multiple owners...
    pid_kv = process_text.split(",")[1]
    print("D", pid_kv)
    pid_str = pid_kv.split("=")[1]

    # Its an int, but we will just use it as a string in an open
    return pid_str


def _pid2cmdline(pid_str):
    with open(f"/proc/{pid_str}/cmdline", "r") as f:
        buf = f.read(1024)

    return buf.replace("\x00", " ").strip()


def _tuple2desc(server, client):
    pid_str = _tuple2pid(server, client)
    if pid_str is None:
        return "Remote"

    cmdline = _pid2cmdline(pid_str)
    desc = f"pid={pid_str}, {cmdline}"
    return desc


class PagesLogin(hc.http.Pages.Login):
    def set_attribs(self, handler):
        # Add our custom fields to the login page

        self.attribs["Desc"] = _tuple2desc(
                handler.server.server_address,
                handler.client_address,
            )
        self.attribs["UUID"] = handler.get_cookie("uuid")
        super().set_attribs(handler)


class PagesQuery(hc.http.Pages.Base):
    def __init__(self, data):
        self.queries = data
        super().__init__()

    def do_POST(self, handler):
        form = handler.get_formdata()

        if b"q" in form:
            query = form[b"q"][0].decode("utf8")

            # FIXME: better id
            _id = hc.http.WebSite._encoded_uuid()
            describe = _tuple2desc(
                handler.server.server_address,
                handler.client_address,
            )
            self.queries[_id] = {
                "a": None,
                "h": handler.headers["Host"],
                "q": query,
                "t": handler.time_start,
                "desc": describe,
            }
            handler.send_header("Location", f"{handler.path}/{_id}")
            handler.send_page(HTTPStatus.CREATED, str(_id))
            return

        if b"_action" in form:
            if not handler.session.has_auth:
                handler.send_error(HTTPStatus.UNAUTHORIZED)
                return

            action = form[b"_action"][0].decode("utf8")
            row = form[b"_row"][0].decode("utf8")

            if action == "del":
                del self.queries[row]
            elif action == "allow":
                self.queries[row]["a"] = True
            elif action == "deny":
                self.queries[row]["a"] = False
            elif action == "edit":
                q_safe = urllib.parse.quote(self.queries[row]["q"])
                handler.send_header("Location", f"/kv/{q_safe}")
                # TODO: hardcodes the location of kv
                handler.send_error(HTTPStatus.SEE_OTHER)
                return
            else:
                handler.send_error(HTTPStatus.BAD_REQUEST)
                return

            # Make refreshing nicer
            handler.send_header("Location", handler.path)
            handler.send_error(HTTPStatus.SEE_OTHER)
            return

    def do_GET(self, handler):
        data = []
        head = handler.config.Widget.head("Queries")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()
        data += ["""
         <form method="post">
          <input type="text" name="q" required autofocus>
          <button name="qq" value="query">query</button>
         </form>
        """]

        if handler.session.has_auth:
            table = handler.config.Widget.table()
            table.style = "sortable"
            table.data = self.queries
            table.columns = {
                "t": "Created",
                "q": "Query",
                "h": "Host",
                "desc": None,
                "a": "Allowed",
            }
            table.actions = ["allow", "deny", "del", "edit"]
            table.update_head(head)
            data += [table]

        data += ["""
          </body>
         </html>
        """]

        handler.send_page(HTTPStatus.OK, data)


class PagesQueryAnswer(hc.http.Pages.Base):
    def __init__(self, data, kv):
        self.queries = data
        self.kv = kv
        super().__init__()

    def do_GET(self, handler):
        # TODO: hardcodes how deep the subtree is
        _, q, _id = handler.path.split("/")

        try:
            query = self.queries[_id]
        except KeyError:
            handler.send_error(HTTPStatus.NOT_FOUND)
            return

        try:
            allowed = query["a"]
        except KeyError:
            allowed = False

        if not allowed:
            handler.send_error(HTTPStatus.FORBIDDEN)
            return

        try:
            answer = self.kv[query["q"]]
        except KeyError:
            handler.send_error(HTTPStatus.CONFLICT)
            return

        handler.send_page(HTTPStatus.OK, answer)


class PagesChat(hc.http.Pages.Base):
    need_auth = True

    def __init__(self, chat_data):
        self.chat = chat_data
        super().__init__()

    def do_POST(self, handler):
        form = handler.get_formdata()
        chat = form[b"chat"][0].decode("utf8")
        note = handler.session.user + ":" + chat
        self.chat.append(note)

        # TODO: refactor to never chain
        return self.do_GET(handler)

    def do_GET(self, handler):
        data = []
        head = handler.config.Widget.head("Chat")
        head.stylesheets.add("/style.css")
        data += [head]
        data += ["<body>"]
        data += handler.config.Widget.navbar()
        data += ["<table>"]

        for i in self.chat:
            data += [f"""
             <tr><td>{i}
            """]

        data += ["""
         <tr>
          <td>
           <form method="post">
            <input type="text" id="chat" name="chat" required autofocus>
            <input type="submit" value="Submit">
           </form>
         </table>
        """]

        handler.send_page(HTTPStatus.OK, data)


class SimpleSite(hc.http.WebSite.RequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _check_uuid(self):
        """Ensure that every visitor gets a unique identifier"""
        if self.get_cookie("uuid") is not None:
            return

        cookie = hc.http.WebSite._encoded_uuid()

        attribs = {
            "Expires": "Mon, 1-Jan-2035 00:00:00 GMT",
            "HttpOnly": None,
            "Max-Age": 315360000,
            "SameSite": "Lax",
            "Path": "/",
        }

        if self.config.cookie_domain:
            attribs["Domain"] = self.config.cookie_domain

        self.send_cookie("uuid", cookie, **attribs)

    def do_GET(self):
        self._check_uuid()
        self.render_page()

    def do_POST(self):
        self._check_uuid()
        self.render_page()


class SimpleSiteConfig(hc.http.WebSite.Config):
    def __init__(self):
        super().__init__()
        self.cookie_domain = None


def argparser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "-d", "--debug",
        action="store_true",
    )
    ap.add_argument(
        "--cookie_domain",
        help="What cookie domain to use for uuid",
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


def main():
    args = argparser()

    data_chat = []
    data_kv = {}
    data_query = {}

    style = """
        table.w {
         border-collapse: collapse;
        }
        td.w {
         border-style: solid;
         border-width: 1px;
        }
    """

    config = SimpleSiteConfig()
    config.cookie_domain = args.cookie_domain
    config.auth = hc.http.Auth.Test()
    config.routes = {
        "/auth/login": PagesLogin(),
        "/auth/list": hc.http.Pages.AuthList(),
        "/kv": hc.http.Pages.KV(data_kv),
        "/metrics": hc.http.Pages.Metrics(),
        "/q": PagesQuery(data_query),
        "/sitemap": hc.http.Pages.SiteMap(),
        "/test/notes": PagesChat(data_chat),
        "/test/page": hc.http.Pages.Static("A Testable Page"),
        "/style.css": hc.http.Pages.Static(
            style,
            content_type="text/css",
        ),
        "/static/sortable.js": hc.http.Pages.StaticFile(
            "static/sortable.js",
            content_type="application/javascript; charset=utf-8",
        ),
        "/static/sortable.css": hc.http.Pages.StaticFile(
            "static/sortable.css",
            content_type="text/css; charset=utf-8",
        ),
    }
    config.routes_subtree = {
        "/kv/": hc.http.Pages.KVEdit(data_kv),
        "/q/": PagesQueryAnswer(data_query, data_kv),
    }

    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(SimpleSite, config)

    httpd = socketserver.TCPServer(("", args.port), handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return


if __name__ == '__main__':
    main()
