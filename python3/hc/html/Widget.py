from types import MappingProxyType


class DefaultHead:
    def __init__(self):
        self.title = None
        self.stylesheets = set()
        self.scripts = set()
        self.meta = []

    def __repr__(self):
        r = []
        r += ["<!DOCTYPE html>\n"]
        r += ["<html>\n"]
        r += ["<head>\n"]
        if self.meta:
            for meta in self.meta:
                r += [f'<meta {meta}>']
        if self.title:
            r += [f"<title>{self.title}</title>\n"]
        for url in self.stylesheets:
            r += [f'<link rel="stylesheet" type="text/css" href="{url}" />\n']
        for url in self.scripts:
            r += [f'<script src="{url}"></script>\n']
        r += ["</head>\n"]
        return "".join(r)


class DefaultTable:
    def __init__(self):
        self.style = "w"
        self.caption = None
        self.data = None
        self.actions = []
        self.columns = {}

    def __str__(self):
        """Given a dict of dicts, output a nice table"""

        r = []
        r += [f'<table class="{self.style}">\n']
        if self.caption:
            r += [f"<caption>{self.caption}</caption>\n"]
        r += ["""
          <thead>
           <tr>
        """]

        for k, column in self.columns.items():
            if column is None:
                column = k
            r += [f"""
             <th>
              <button>
               {column}
               <span aria-hidden="true"></span>
              </button>
             </th>
            """]

        if self.actions:
            r += ['<th>Action']

        r += ["""
          </thead>
          <tbody>
        """]

        # TODO: also support list()

        for k, row in self.data.items():
            r += ["<tr>"]
            for column in self.columns.keys():
                if column is None:
                    val = k
                else:
                    if isinstance(row, (dict, MappingProxyType)):
                        val = row[column]
                    else:
                        val = row
                r += [f"<td>{val}</td>\n"]

            if self.actions:
                r += ["<td>"]
                r += ["<form method=post>"]
                r += [f'<input type=hidden name=_row value="{k}"/>']
                for action in self.actions:
                    r += [
                        f'<button name="_action" value="{action}">',
                        action,
                        '</button>',
                    ]
                r += ["</form>"]
            r += ["</tr>\n"]

        r += ["""
         </tbody>
         </table>
        """]
        return "".join(r)

    def update_head(self, head, subdir="/static"):
        head.stylesheets.add(f"{subdir}/sortable.css")
        head.scripts.add(f"{subdir}/sortable.js")


class Default:
    @classmethod
    def head(cls, title):
        obj = DefaultHead()
        obj.title = title
        return obj

    @classmethod
    def navbar(cls):
        r = []
        r += ['<a href="/sitemap">sitemap</a>']
        # TODO: the above hardcodes the location of the sitemap
        return r

    @classmethod
    def table(cls):
        return DefaultTable()
