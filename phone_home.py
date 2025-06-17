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
import hc.http.sqlite   # noqa: E402


def argparser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "-d", "--debug",
        action="store_true",
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
        head = handler.config.Widget.head("Phone Home")
        head.add_stylesheet("/style.css")
        head.add_script("/sortable.js")
        # TODO: this harcodes the location of the javascript
        data += [head]

        data += handler.config.Widget.navbar()

        if not handler.session.has_auth:
            handler.send_error(HTTPStatus.UNAUTHORIZED)
            return

        # data += ["""
        #  <form method="post">
        # """]

        data += handler.config.Widget.show_dict2(
            self.data,
            ["instance_id", "hostname", "fqdn", "pub_key_ed25519"],
            ["del"],
        )

        # data += ["</form>"]

        data += ["""
          </body>
         </html>
        """]

        data = [str(x) for x in data]
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

.sr-only {
  position: absolute;
  top: -30em;
}

table.sortable td,
table.sortable th {
  padding: 0.125em 0.25em;
  width: 8em;
}

table.sortable th {
  font-weight: bold;
  border-bottom: thin solid #888;
  position: relative;
}

table.sortable th.no-sort {
  padding-top: 0.35em;
}

table.sortable th:nth-child(5) {
  width: 10em;
}

table.sortable th button {
  padding: 4px;
  margin: 1px;
  font-size: 100%;
  font-weight: bold;
  background: transparent;
  border: none;
  display: inline;
  right: 0;
  left: 0;
  top: 0;
  bottom: 0;
  width: 100%;
  text-align: left;
  outline: none;
  cursor: pointer;
}

table.sortable th button span {
  position: absolute;
  right: 4px;
}

table.sortable th[aria-sort="descending"] span::after {
  content: "▼";
  color: currentcolor;
  font-size: 100%;
  top: 0;
}

table.sortable th[aria-sort="ascending"] span::after {
  content: "▲";
  color: currentcolor;
  font-size: 100%;
  top: 0;
}

table.show-unsorted-icon th:not([aria-sort]) button span::after {
  content: "♢";
  color: currentcolor;
  font-size: 100%;
  position: relative;
  top: -3px;
  left: -4px;
}

table.sortable td.num {
  text-align: right;
}

table.sortable tbody tr:nth-child(odd) {
  background-color: #ddd;
}

/* Focus and hover styling */

table.sortable th button:focus,
table.sortable th button:hover {
  padding: 2px;
  border: 2px solid currentcolor;
  background-color: #e5f4ff;
}

table.sortable th button:focus span,
table.sortable th button:hover span {
  right: 2px;
}

table.sortable th:not([aria-sort]) button:focus span::after,
table.sortable th:not([aria-sort]) button:hover span::after {
  content: "▼";
  color: currentcolor;
  font-size: 100%;
  top: 0;
}
    """

    js = """
/*
 *   This content is licensed according to the W3C Software License at
 *   https://www.w3.org/Consortium/Legal/2015/copyright-software-and-document
 *
 *   File:   sortable-table.js
 *
 *   Desc:   Adds sorting to a HTML data table that implements ARIA Authoring
             Practices
 */

'use strict';

class SortableTable {
  constructor(tableNode) {
    this.tableNode = tableNode;

    this.columnHeaders = tableNode.querySelectorAll('thead th');

    this.sortColumns = [];

    for (var i = 0; i < this.columnHeaders.length; i++) {
      var ch = this.columnHeaders[i];
      var buttonNode = ch.querySelector('button');
      if (buttonNode) {
        this.sortColumns.push(i);
        buttonNode.setAttribute('data-column-index', i);
        buttonNode.addEventListener('click', this.handleClick.bind(this));
      }
    }

    this.optionCheckbox = document.querySelector(
      'input[type="checkbox"][value="show-unsorted-icon"]'
    );

    if (this.optionCheckbox) {
      this.optionCheckbox.addEventListener(
        'change',
        this.handleOptionChange.bind(this)
      );
      if (this.optionCheckbox.checked) {
        this.tableNode.classList.add('show-unsorted-icon');
      }
    }
  }

  setColumnHeaderSort(columnIndex) {
    if (typeof columnIndex === 'string') {
      columnIndex = parseInt(columnIndex);
    }

    for (var i = 0; i < this.columnHeaders.length; i++) {
      var ch = this.columnHeaders[i];
      var buttonNode = ch.querySelector('button');
      if (i === columnIndex) {
        var value = ch.getAttribute('aria-sort');
        if (value === 'descending') {
          ch.setAttribute('aria-sort', 'ascending');
          this.sortColumn(
            columnIndex,
            'ascending',
            ch.classList.contains('num')
          );
        } else {
          ch.setAttribute('aria-sort', 'descending');
          this.sortColumn(
            columnIndex,
            'descending',
            ch.classList.contains('num')
          );
        }
      } else {
        if (ch.hasAttribute('aria-sort') && buttonNode) {
          ch.removeAttribute('aria-sort');
        }
      }
    }
  }

  sortColumn(columnIndex, sortValue, isNumber) {
    function compareValues(a, b) {
      if (sortValue === 'ascending') {
        if (a.value === b.value) {
          return 0;
        } else {
          if (isNumber) {
            return a.value - b.value;
          } else {
            return a.value < b.value ? -1 : 1;
          }
        }
      } else {
        if (a.value === b.value) {
          return 0;
        } else {
          if (isNumber) {
            return b.value - a.value;
          } else {
            return a.value > b.value ? -1 : 1;
          }
        }
      }
    }

    if (typeof isNumber !== 'boolean') {
      isNumber = false;
    }

    var tbodyNode = this.tableNode.querySelector('tbody');
    var rowNodes = [];
    var dataCells = [];

    var rowNode = tbodyNode.firstElementChild;

    var index = 0;
    while (rowNode) {
      rowNodes.push(rowNode);
      var rowCells = rowNode.querySelectorAll('th, td');
      var dataCell = rowCells[columnIndex];

      var data = {};
      data.index = index;
      data.value = dataCell.textContent.toLowerCase().trim();
      if (isNumber) {
        data.value = parseFloat(data.value);
      }
      dataCells.push(data);
      rowNode = rowNode.nextElementSibling;
      index += 1;
    }

    dataCells.sort(compareValues);

    // remove rows
    while (tbodyNode.firstChild) {
      tbodyNode.removeChild(tbodyNode.lastChild);
    }

    // add sorted rows
    for (var i = 0; i < dataCells.length; i += 1) {
      tbodyNode.appendChild(rowNodes[dataCells[i].index]);
    }
  }

  /* EVENT HANDLERS */

  handleClick(event) {
    var tgt = event.currentTarget;
    this.setColumnHeaderSort(tgt.getAttribute('data-column-index'));
  }

  handleOptionChange(event) {
    var tgt = event.currentTarget;

    if (tgt.checked) {
      this.tableNode.classList.add('show-unsorted-icon');
    } else {
      this.tableNode.classList.remove('show-unsorted-icon');
    }
  }
}

// Initialize sortable table buttons
window.addEventListener('load', function () {
  var sortableTables = document.querySelectorAll('table.sortable');
  for (var i = 0; i < sortableTables.length; i++) {
    new SortableTable(sortableTables[i]);
  }
});
"""

    config = hc.http.WebSite.Config()
    if args.db:
        config.auth = hc.http.sqlite.Authenticator(args.db)
    else:
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
        "/sortable.js": hc.http.WebSite.PagesStatic(
            js,
            content_type="application/javascript",
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
