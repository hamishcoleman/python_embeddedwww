#!/usr/bin/env python3
"""Simple http website to show directory of camera images"""
#

import argparse
import datetime
import functools
import glob
import os
import shutil
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
import hc.http.Signer   # noqa: E402
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


class PagesCamera(hc.http.Pages.Base):
    need_auth = True
    has_params = [
        "start",
    ]

    def __init__(self, directory):
        if not os.path.isdir(directory):
            raise ValueError(f"not a dir: {directory}")
        self.dir = directory
        super().__init__()

    @staticmethod
    def _img2url(handler, filename):
        # Hardcodes the img url path
        path = f"/raw/{filename}"
        return handler.config.signer.create_url(path)

    def do_GET(self, handler):
        start = int(handler.param.get("start", ["0"])[0])
        count = 18

        # Index the directory
        index = {}
        for filename in glob.glob(f"{self.dir}/*.jpg"):
            mtime = int(os.stat(filename).st_mtime)
            this = {
                "img": os.path.basename(filename),
            }
            mov = f'{os.path.splitext(this["img"])[0]}.mp4'
            this["mov"] = mov
            index[mtime] = this

        # Filter the index for just the view we want
        times = sorted(index, reverse=True)
        if start == 0:
            start_index = 0
        else:
            i = 0
            while True:
                if i > len(times):
                    i = len(times) + 1
                    break

                if times[i] <= start:
                    break

                i += 1

            start_index = max(i, 0)

        page = []
        head = handler.config.Widget.head("Camera")
        head.stylesheets.add("/style.css")
        page += [head]
        page += ["<body>"]
        page += handler.config.Widget.navbar()

        prev_time = times[max(start_index - count, 0)]
        next_time = times[min(start_index + count, len(index) - 1)]
        page += [
            '<form method="get">',
            '<button name="start" value="0">&lt;&lt;</button>',
            f'<button name="start" value="{prev_time}">&lt;</button>',
            start_index,
            " - ",
            start_index + count - 1,
            " of ",
            len(index),
            f'<button name="start" value="{next_time}">&gt;</button>',
            "</form>",
        ]

        page += ['<div class="gallery">']
        for i in times[start_index:start_index+count]:
            this = index[i]
            dt = datetime.datetime.fromtimestamp(i)
            # TODO: actually implement thumbnailing in the PagesImages class?
            # thumb = "/img/tn/" + this["img"]
            img = self._img2url(handler, this["img"])
            mov = self._img2url(handler, this["mov"])
            page += [
                '<div class="gallery_item">',
                f'<a href="{img}">',
                f'<img src="{img}" width="192" height="108">',
                '</a>',
                '<div class="desc">',
                f'<a href="{mov}">',
                dt.isoformat(timespec="minutes"),
                '</a>',
                '</div>',
                '</div>',
            ]
        page += ["</div>"]
        page += ["</body></html>"]
        handler.send_page(
            HTTPStatus.OK,
            page,
        )


# TODO:
# - refactor this into a reusable class
class PagesImages(hc.http.Pages.Base):
    need_auth = True
    enable_signedurl = True

    def __init__(self, directory):
        if not os.path.isdir(directory):
            raise ValueError(f"not a dir: {directory}")
        self.dir = directory
        super().__init__()

        # the camera page sticks lots of these up
        self.tbf = hc.http.GCRA.Filter(100, 1000)

    def do_GET(self, handler):
        # TODO: hardcodes how deep the subtree is
        _, _, q, _id = handler.path.split("/")

        if q not in ["tn", "f"]:
            handler.send_error(HTTPStatus.NOT_FOUND)
            return

        filename = f"{self.dir}/{_id}"

        if filename.endswith(".jpg"):
            content_type = "image/jpeg"
        elif filename.endswith(".mp4"):
            content_type = "video/mp4"
        else:
            handler.send_error(HTTPStatus.NOT_FOUND)
            return

        try:
            fh = open(filename, "rb")
        except (
            FileNotFoundError,
            IsADirectoryError,
        ):
            handler.send_error(HTTPStatus.NOT_FOUND)
            return

        handler.send_response(HTTPStatus.OK)
        handler.send_header("Content-type", content_type)
        handler.end_headers()

        try:
            shutil.copyfileobj(fh, handler.wfile)
        except ConnectionResetError:
            # close?
            return


class RequestHandler(hc.http.WebSite.RequestHandler):
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

    style = """
        div.gallery {
          display: flex;
          flex-wrap: wrap;
          justify-content: flex-start;
        }

        div.gallery_item {
          margin: 5px;
          border: 1px solid #ccc;
          width: 192px;
        }

        div.gallery_item:hover {
          border: 1px solid #777;
        }

        div.gallery_item img {
          width: 100%;
          height: auto;
        }

        div.gallery_item div.desc {
          padding: 15px;
          text-align: center;
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
        webconfig.auth.secret = config["jwtsecret"].encode("utf8")

    if "signingsecret" in config:
        webconfig.signer = hc.http.Signer.Simple(
            config["signingsecret"].encode("utf8"),
        )

    hc.http.pages.add_routes(webconfig.routes)
    webconfig.Widget.add_routes(webconfig.routes)

    webconfig.routes.update({
        "/style.css": hc.http.Pages.Static(
            style,
            content_type="text/css; charset=utf-8",
        ),
        # "/"   - redirect either to app or to login
        "/camera": PagesCamera(config["camera"]["dir"]),

        # Some endpoints are handled by nginx, but I want them on the sitemap
        "/player.html": hc.http.Pages.Static("fake"),
        "/raw": hc.http.Pages.Static("fake"),
    })
    webconfig.routes_subtree = {
        "/img/": PagesImages(config["camera"]["dir"]),
    }

    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(RequestHandler, webconfig)

    httpd = socketserver.TCPServer(("", args.port), handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return


if __name__ == '__main__':
    main()
