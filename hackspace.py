#!/usr/bin/env python3
"""Reproduce the DSL hackman, with as little code as possible"""

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


import hc.html.Widget   # noqa: E402
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


class Widget(hc.html.Widget.Default):
    @classmethod
    def head(cls, title):
        r = []
        r += f"""<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
"""
        r += cls.style()
        r += "</head>"
        return r

    @classmethod
    def navbar(cls):
        r = []
        r += """
    <header>
      <table width=100%>
        <tr>
          <td>
            <a href="/" style="color: white;">
              <img src="/static/dsl_logo.svg" width="30px" />
              Dim Sum Labs
            </a>
            <a href="/sitemap">sitemap</a>
          <td align=right valign=bottom>
"""
        # TODO:
        # Logged in as {session.user}, <a href="/logout/"
        # style="color:white;">Logout</a>
        r += """
      </table>
    </header>
"""
        # TODO: the above hardcodes the location of the sitemap
        return r


class RequestHandler(hc.http.WebSite.RequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.render_page()

    def do_POST(self):
        self.render_page()


class PagesAccount(hc.http.WebSite.Pages):
    need_auth = True

    def do_GET(self, handler):
        data = []
        data += handler.config.Widget.head("DSL Door")
        data += "<body>\n"
        data += handler.config.Widget.navbar()
        data += """
    <main>


  <h2>Account actions</h2>
  <ul class="action-list">
    <li>
      <p> By clicking the 'Inform' button, you are agreeing that you
      have already paid or are about to pay right now.
        <form action="/payment_submit/" method="POST">
          <input type="hidden" name="csrfmiddlewaretoken" value="EiaB6QC5sF">
          <div>

      <label for="id_year_month">Inform the door of a payment:</label>

    <select name="year_month" id="id_year_month">
  <option value="2025-05">2025-05</option>

  <option value="2025-06">2025-06</option>

  <option value="2025-07">2025-07</option>

</select>

</div>
          <input type="submit" value="Inform">
        </form>
      </p>
    </li>
"""

        data += """
    <p>The door's database says your dues are paid until 2020-11
"""

        data += """
    <hr />

    <li>
      <form action="/rfid_pair/" method="POST">
        <input type="hidden" name="csrfmiddlewaretoken" value="EiaB6QC5sFh">
        <div>

      <label for="id_card_id">Pair by card ID (defaults to last seen):</label>

    <input type="text" name="card_id" value="766" required id="id_card_id">

</div>
        <input type="submit" value="Pair">
      </form>
    </li>

    <hr />

    <li>
      <p>
        &nbsp;&nbsp;<a href="/password_change/">Change password</a>
      </p>
    </li>

    <hr />

    <li>
      <p>
        &nbsp;&nbsp;<a href="/">Back to space actions</a>
      </p>
    </li>

  </ul>

    </main>
"""

        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)


class PagesRoot(hc.http.WebSite.Pages):
    def do_GET(self, handler):
        if not handler.session.has_auth:
            handler.send_header("Location", "/login")
            # TODO: hardcodes the location of login
            handler.send_error(HTTPStatus.SEE_OTHER)

        data = []
        data += handler.config.Widget.head("DSL Door")
        data += "<body>\n"
        data += handler.config.Widget.navbar()
        data += """
    <main>


  <h2>Space actions</h2>
  <ul class="action-list">
    <li>
      <form action="/door_open/" method="GET">
        <input
          type="submit"
          name="open"
          value="Open door"
          style="width: 100%; height: 50px;"
        >
      </form>
    </li>
  </ul>

  <hr />

  <h2>Navigation</h2>
  <p>
    &nbsp;&nbsp;<a href="/account_actions/">Account actions</a>
  </p>


    </main>
"""

        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)


def main():
    args = argparser()

    # data_x = yz

    style = """
header {
    background-color: #464646;
    padding: 0px;
    margin: 0px;
    color: #ffffff;
}

body {
    padding: 0px;
    margin: 0px;
    font-family: "Helvetica Neue",Helvetica,Arial,sans-serif;
    font-size: 20px;
}

main {
    padding-left: 20px;
    padding-right: 20px;
}

footer {
    border-top: 1px solid #464646;
    width: 100%;
    position : absolute;
    bottom : 0;
    margin-top: 20px;
}

label {
    display: inline-block;
    width: 160px;
    text-align: right;
}

#dsl {
    margin: 0px;
    color: #ffffff;
    padding-left: 20px;
    padding-right: 20px;
}

.action-list {
    list-style-type: none;
    padding: 0px;
}

.action-list > li {
    margin-bottom: 10px;
}

a.button {
    -webkit-appearance: button;
    -moz-appearance: button;
    appearance: button;
    text-decoration: none;
    color: initial;
}

.input-number-nospinner {
    -moz-appearance: textfield;
    -webkit-appearance: none;
}

ul.messages {
    list-style-type: none;
    padding: 0px;
}

ul.messages > li {
    color: "#00b115";
}
"""

    logo = """<?xml version="1.0" encoding="utf-8"?>
<!-- Generator: Adobe Illustrator 16.2.0, SVG Export Plug-In . SVG Version: 6.00 Build 0)  -->
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
     width="210px" height="210px" viewBox="0 0 210 210" enable-background="new 0 0 210 210" xml:space="preserve">
<g>
    <path fill="#E01F30" d="M182.444,108.507c0.197,0.899,0.259,1.834,0.197,2.774l-0.78,11.352c-0.005,0.145-0.022,0.287-0.033,0.416
        l0.026,0.137c0.156,0.777,0.226,1.568,0.195,2.365l-0.013,0.371l0.218,2.098c0.028,0.262,0.047,0.527,0.053,0.787l0.513,19.738
        c0.028,1.121-0.132,2.24-0.47,3.313l-1.143,3.563c-1.402,4.42-5.65,7.396-10.406,7.396c-0.254,0-0.521-0.01-0.785-0.025
        l-2.879-0.201c-0.43-0.031-0.838-0.078-1.244-0.156l-1.036,3.289c-1.399,4.422-5.652,7.408-10.414,7.408
        c-0.251,0-0.513-0.01-0.757-0.023l-2.899-0.193c-0.604-0.041-1.185-0.123-1.752-0.258l-0.989,3.115
        c-1.402,4.424-5.656,7.416-10.416,7.416c-0.26,0-0.521-0.008-0.785-0.027l-2.889-0.197c-0.833-0.063-1.638-0.209-2.406-0.43
        l-0.826,2.584c-1.411,4.412-5.655,7.383-10.409,7.383c-0.261,0-0.519-0.008-0.781-0.027l-2.882-0.197
        c-5.546-0.383-9.904-4.707-10.105-10.039l-0.42-10.865l-1.539-0.311l-2.412,1.717c-1.939,1.387-4.213,2.057-6.479,2.057
        c-1.495,0-2.988-0.289-4.367-0.869c-0.42,2.27-1.626,4.363-3.438,5.924l-2.068,1.785c-2.039,1.748-4.639,2.67-7.279,2.67
        c-1.391,0-2.79-0.258-4.126-0.781l-2.076-0.814c-0.234-0.1-0.48-0.205-0.709-0.313c-0.642,2.33-2.108,4.4-4.191,5.834l-2.528,1.738
        c-1.907,1.314-4.129,1.959-6.333,1.959c-2.917,0-5.813-1.119-7.941-3.291l-2.907-2.965c-1.896-1.938-2.952-4.502-2.952-7.16v-18.74
        c-3.496-1.762-5.816-5.275-5.816-9.244l0.002-13.469c0-0.789,0.102-1.58,0.285-2.354l0.233-0.973
        c0.192-0.777,0.462-1.52,0.817-2.215c-6.778-7.902-8.824-17.159-9.938-22.193C22.639,74.152,33.9,47.204,63.848,29.269
        c2.037-1.453,5.007-3.416,8.955-3.416c1.127,0,2.213,0.162,3.26,0.456c3.985-4.011,7.136-5.855,9.497-6.607l0.209-0.089
        c1.572-0.683,4.496-1.941,8.955-1.941c2.734,0,5.673,0.481,8.973,1.465c0.982,0.296,1.936,0.67,2.875,1.127
        c1.34-0.535,2.782-0.825,4.249-0.825c0.767,0.005,1.526,0.084,2.295,0.239c0.103,0.024,8.517,1.886,17.183,6.951
        c1.51-0.716,3.185-1.107,4.908-1.107c0.398,0,0.815,0.021,1.208,0.062c16.28,1.693,29.57,9.841,38.427,23.554
        c11.944,18.494,12.849,43.062,7.631,56.948c-0.045,0.171-0.103,0.394-0.139,0.63C182.427,107.315,182.462,107.913,182.444,108.507z
        "/>
    <path fill="#FFFFFF" d="M135.284,35.974h-0.031c-0.99,0,3.221,6.678,7.465,13.349c4.25,6.675,8.529,13.346,7.65,13.346
        c-0.021,0-0.049,0-0.064-0.006c-0.971-0.268-9.316-14.026-19.908-23.104c-7.9-6.751-18.785-9.502-19.545-9.662h-0.025
        c-1.188,0,9.906,22.063,11.332,32.147c1.867,13.209,3.24,27.979,3.24,27.979s-10.619-56.642-24.895-60.906
        c-2.425-0.725-4.276-0.993-5.731-0.993c-3.006,0-4.333,1.115-5.765,1.504c-3.604,1.005-11.811,11.104-18.845,22.88
        c-3.312,5.553-5.239,16.635-4.695,19.397c-3.707-18.472,9.774-35.598,7.383-35.598c-0.408,0-1.277,0.505-2.813,1.606
        c-37.707,22.341-32.083,55.118-28.969,69.298c1.37,6.199,3.8,16.096,12.622,22.127c0.046,0.203,0.081,0.402,0.119,0.574
        l0.022,0.008c0.006,0.037,0,0.072,0,0.115c0.249,1.174,0.237,1.563-1.438,3.51l-0.377,0.033c-0.091,0.088-0.142,0.131-0.147,0.145
        l46.271,8.605l-48.003-6.199l-0.231,0.975v13.461l5.808,0.912v27.072l2.91,2.967l2.522-1.74l0.056-27.422l15.084,2.939
        l0.236,17.781l2.076,0.816l2.066-1.783l0.059-16.43l13.588,2.68l0.257,4.738l1.168,1.285l2.595-1.846l0.079-3.373l11.309,2.236
        l5.002-3.195l0.684-0.42l-0.082-1.887l1.111-0.992l1.039,26.943l2.885,0.201l1.139-3.564l-0.506-19.738l0.012-2.23l0.006-1.842
        l0.014-0.01l-0.053-1.328l-3.566-4.971l4.666,3.982l0.045,1.654l8.996-5.432l1.346-0.813l0.092-1.23l1.107-0.742l0.303,5.576
        l0.828,21.166l2.891,0.201l1.129-3.561l-0.514-19.748l-0.049-1.646l0.092-2.699l-0.076-1.557l-3.553-4.973l4.672,3.984l0.033,1.447
        l8.629-5.484l1.412-0.854v-1.027l1.07-0.848l1.064,26.717l2.896,0.193l1.131-3.555l-0.516-19.74l-0.127-2.791l0.061-1.703h-0.004
        l-0.092-1.891l-3.553-4.973l4.672,3.984l0.035,1.6l9.283-6.137l0.6-0.344v-0.818l1.004-0.508l0.992,26.361l2.881,0.197l1.133-3.563
        l-0.512-19.736l-0.297-2.795l0.041-1.072l-0.191-0.961l-0.023-0.02l0.008-0.051l-0.084-0.371l-3.551-4.975
        c0,0,2.307,1.959,3.674,3.125l0.777-11.348L130.476,134.6c0,0,39.068-24.506,40.385-25.98l0.744-0.357l-0.26-0.549
        c-0.014-0.176,0.104-2.787,0.873-5.014C179.325,84.151,172.356,39.836,135.284,35.974z"/>
</g>
</svg>
"""  # noqa: E501

    config = hc.http.WebSite.Config()
    config.Widget = Widget
    config.auth = hc.http.WebSite.Authenticator()
    config.routes = {
        "/": PagesRoot(),
        "/login": hc.http.WebSite.PagesLogin(),
        "/account_actions/": PagesAccount(),
        # /payment_submit/
        # /rfid_pair/
        # /password_change/
        # /door_open/

        "/style.css": hc.http.WebSite.PagesStatic(
            style,
            content_type="text/css",
        ),
        "/static/dsl_logo.svg": hc.http.WebSite.PagesStatic(
            logo,
            content_type="image/svg+xml",
        ),

        "/auth/list": hc.http.WebSite.PagesAuthList(),
        "/metrics": hc.http.WebSite.PagesMetrics(),
        "/sitemap": hc.http.WebSite.PagesMap(),
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
