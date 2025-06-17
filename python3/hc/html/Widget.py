
class DefaultHead:
    def __init__(self, title):
        self.title = title
        self.stylesheets = []

    def __repr__(self):
        r = []
        r += ["<!DOCTYPE html>\n"]
        r += ["<html>\n"]
        r += ["<head>\n"]
        r += [f"<title>{self.title}</title>\n"]
        for url in self.stylesheets:
            r += [f'<link rel="stylesheet" type="text/css" href="{url}" />\n']
        r += ["</head>\n"]
        return "".join(r)

    def add_stylesheet(self, url):
        self.stylesheets.append(url)


class Default:
    @classmethod
    def style(cls):
        r = []
        r += ['<link rel="stylesheet" type="text/css" href="/style.css" />']
        return r

    @classmethod
    def head(cls, title):
        obj = DefaultHead(title)
        obj.add_stylesheet("/style.css")
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
    def show_dict2(cls, d, columns, actions):
        """Given a dict of dicts, output a nice table"""

        r = []
        r += ["""
         <table class="sortable">
          <caption>A Caption</caption>
          <thead>
           <tr>
        """]

        for column in columns:
            r += [f"""
             <th>
              <button>
               {column}
              </button>
             </th>
            """]
        r += ['<th>Action<span aria-hidden="true"></span>']
        r += ["""
          </thead>
          <tbody>
        """]

        for k, row in d.items():
            r += ["<tr>"]
            for column in columns:
                r += [f"<td>{row[column]}</td>"]
            r += ["<td>"]
            for action in actions:
                r += [f"""
                 <button name="a" value="{action}/{k}">{action}</button>
                """]
            r += ["</tr>"]

        r += ["""
         </tbody>
         </table>
        """]
        return r

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
