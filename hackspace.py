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
        obj = super().head(title)
        obj.meta = [
            'charset="utf-8"',
            'http-equiv="X-UA-Compatible" content="IE=edge"',
            'name="viewport" content="width=device-width, initial-scale=1"',
            'http-equiv="Content-Type" content="text/html; charset=utf-8"',
        ]
        obj.stylesheets += ["/static/style.css"]
        return obj

    @classmethod
    def navbar(cls, username=None):
        r = []
        r += ["""
    <header>
      <table width=100%>
        <tr>
          <td>
            <a href="/" style="color: white;">
              <img src="/static/dsl_logo.svg" width="30px" />
              Dim Sum Labs
            </a>
          <td align=right valign=bottom>
"""]
        if username:
            r += [f"Logged in as {username}, "]
            r += ['<a href="/logout/" style="color:white;">Logout</a>']

        r += ["""
      </table>
    </header>
"""]
        return r


class RequestHandler(hc.http.WebSite.RequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.render_page()

    def do_POST(self):
        self.render_page()


class PagesLogout(hc.http.WebSite.Pages):
    need_auth = True

    def do_GET(self, handler):
        handler.config.auth.end_session(handler.session)
        handler.send_header("Location", "/login")
        # TODO: hardcodes the location of login
        handler.send_error(HTTPStatus.SEE_OTHER)


class PagesAccount(hc.http.WebSite.Pages):
    need_auth = True

    def do_GET(self, handler):

        # TODO:
        # fetch these details from the database
        months_next = [
            "2025-05",
            "2025-06",
            "2025-07",
        ]
        user_paid_until = "2020-11"
        rfid_id_last_seen = "766"

        data = []
        head = handler.config.Widget.head("DSL Door")
        data += [head]
        data += ["<body>\n"]
        data += handler.config.Widget.navbar(handler.session.user)
        data += ["""
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
"""]
        for month in months_next:
            data += [f'<option value="{month}">{month}</option>\n']

        data += [f"""
</select>

</div>
          <input type="submit" value="Inform">
        </form>
      </p>
    </li>

    <p>The door's database says your dues are paid until {user_paid_until}

    <hr />

    <li>
      <form action="/rfid_pair/" method="POST">
        <input type="hidden" name="csrfmiddlewaretoken" value="EiaB6QC5sFh">
        <div>

      <label for="id_card_id">Pair by card ID (defaults to last seen):</label>

    <input
      type="text"
      name="card_id"
      value="{rfid_id_last_seen}"
      required id="id_card_id"
    >

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
"""]

        data = [str(x) for x in data]
        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)


class PagesPayment(hc.http.WebSite.Pages):
    need_auth = True

    def do_POST(self, handler):
        form = handler.get_formdata()
        year_month = form[b"year_month"][0].decode("utf8")

        # TODO:
        # actually update database with year_month
        user_paid_until = year_month
        valid_form = True

        data = []
        head = handler.config.Widget.head("DSL Door")
        data += [head]
        data += ["<body>\n"]
        data += handler.config.Widget.navbar(handler.session.user)
        data += ["""
    <main>
<h2>Payment Claim Recorded</h2>

"""]
        if valid_form:
            data += [f"""
  <p>The door's database now says your dues are paid until {user_paid_until}
"""]

        data += ["""
<p>INSERT PAPER INSTRUCTIONS HERE
"""]

        data = [str(x) for x in data]
        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)


class PagesPair(hc.http.WebSite.Pages):
    need_auth = True

    def do_POST(self, handler):
        form = handler.get_formdata()
        card_id = form[b"card_id"][0].decode("utf8")

        # TODO:
        # actually update database with year_month
        user_card_id = card_id
        rfid_id_in_use = False

        if rfid_id_in_use:
            handler.send_page(HTTPStatus.BAD_REQUEST, "Card already paired")
            return

        data = []
        head = handler.config.Widget.head("DSL Door")
        data += [head]
        data += ["<body>\n"]
        data += handler.config.Widget.navbar(handler.session.user)

        data += [f"""
<h2>Paired card! ({user_card_id})</h2>
"""]

        # TODO:
        # original site posted the "paired" message to a queue that got shown
        # on many pages, then redirected to /account_actions/

        data = [str(x) for x in data]
        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)


class PagesDoor(hc.http.WebSite.Pages):
    need_auth = True

    def do_POST(self, handler):
        # TODO:
        # fetch these details from the database
        user_has_paid = (handler.session.user == "admin")

        if user_has_paid:
            # TODO:
            # Send message to door GPIO
            handler.send_page(HTTPStatus.OK, "Opened door!")
            return

        data = []
        head = handler.config.Widget.head("DSL Door")
        data += [head]
        data += ["<body>\n"]
        data += handler.config.Widget.navbar(handler.session.user)
        data += ["""
<h1>Door Not Opened!</h1>

<hr />
There could be several reasons for this:
<ul>
  <li>You have not paid
  <li>You have paid, but the internet is down
  <li>Payments batch processing might be late
</ul>

If you have paid, please use the
<a href="/account_actions/">Account actions</a>
page to inform the door of your payment.

<p>
If you continue to have trouble with the door, please email us and we will
fix it promptly.

<hr />
<a href="javascript:window.history.back()">Back</a>


"""]

        data = [str(x) for x in data]
        data = "".join(data)
        handler.send_page(HTTPStatus.FORBIDDEN, data)


class PagesRoot(hc.http.WebSite.Pages):
    def do_GET(self, handler):
        if not handler.session.has_auth:
            handler.send_header("Location", "/login")
            # TODO: hardcodes the location of login
            handler.send_error(HTTPStatus.SEE_OTHER)

        data = []
        head = handler.config.Widget.head("DSL Door")
        data += [head]
        data += ["<body>\n"]
        data += handler.config.Widget.navbar(handler.session.user)
        data += ["""
    <main>


  <h2>Space actions</h2>
  <ul class="action-list">
    <li>
      <form action="/door_open/" method="POST">
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
"""]

        data = [str(x) for x in data]
        data = "".join(data)
        handler.send_page(HTTPStatus.OK, data)


def main():
    args = argparser()

    # data_x = yz

    config = hc.http.WebSite.Config()
    config.Widget = Widget
    config.auth = hc.http.WebSite.AuthenticatorTest()
    config.routes = {
        "/": PagesRoot(),
        "/login": hc.http.WebSite.PagesLogin(),
        "/logout/": PagesLogout(),
        "/account_actions/": PagesAccount(),
        "/door_open/": PagesDoor(),
        "/payment_submit/": PagesPayment(),
        "/rfid_pair/": PagesPair(),
        # /password_change/

        "/static/style.css": hc.http.WebSite.PagesStaticFile(
            "static/hackman.css",
            content_type="text/css; charset=utf-8",
        ),
        "/static/dsl_logo.svg": hc.http.WebSite.PagesStatic(
            "static/dsl_logo.svg",
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
