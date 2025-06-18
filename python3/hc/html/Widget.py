
class DefaultHead:
    def __init__(self):
        self.title = None
        self.stylesheets = []
        self.scripts = []
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

    def add_stylesheet(self, url):
        self.stylesheets.append(url)

    def add_script(self, url):
        self.scripts.append(url)


class DefaultTable:
    def __init__(self):
        self.style = "w"
        self.caption = None
        self.data = None
        self.actions = []
        self.columns = []

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

        for column in self.columns:
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
            for column in self.columns:
                r += [f"<td>{row[column]}</td>\n"]
            if self.actions:
                r += ["<td>"]
                for action in self.actions:
                    r += [
                        '<button form="action" name="a" ',
                        f'value="{action}/{k}">{action}</button>',
                    ]
            r += ["</tr>\n"]

        r += ["""
         </tbody>
         </table>
        """]
        return "".join(r)


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
    def show_dict(cls, d, actions):
        r = []
        r += ["""
         <table class="w">
          <tr>
           <th>ID
           <th>Data
           <th>Action
        """]

        for k, v in d.items():
            r += [f"""
             <tr>
              <td class="w">{k}
              <td class="w">{v}
              <td>
            """]
            for action in actions:
                r += [f"""
                 <button name="a" value="{action}/{k}">{action}</button>
                """]

        r += ["""
         </table>
        """]
        return r

    @classmethod
    def show_dict2(cls):
        return DefaultTable()

    @classmethod
    def show_dictlist(cls, dl, actions):
        r = []
        r += ["""
         <table>
          <tr>
           <th>ID
           <th>Data
           <th>Action
        """]

        for i in range(len(dl)):
            r += [f"""
             <tr>
              <td class="w">{i}
              <td class="w">{dl[i]}
              <td>
            """]
            for action in actions:
                r += [f"""
                 <button name="a" value="{action}/{i}">{action}</button>
                """]

        r += ["""
         </table>
        """]
        return r
