
def style():
    r = []
    r += '<link rel="stylesheet" type="text/css" href="/style.css" />'
    return r


def head(title):
    r = []
    r += """<!DOCTYPE html>
     <html>
     <head>
    """
    r += f"<title>{title}</title>"
    r += style()
    r += "</head>"
    return r


def navbar():
    r = []
    r += '<a href="/sitemap">sitemap</a>'
    # TODO: the above hardcodes the location of the sitemap
    return r


def show_dict(d, actions):
    r = []
    r += """
     <table class="w">
      <tr>
       <th>ID
       <th>Data
       <th>Action
    """

    for k, v in d.items():
        r += f"""
         <tr>
          <td class="w">{k}
          <td class="w">{v}
          <td>
        """
        for action in actions:
            r += f"""
             <button name="a" value="{action}/{k}">{action}</button>
            """

    r += """
     </table>
    """
    return r


def show_dictlist(dl, actions):
    r = []
    r += """
     <table>
      <tr>
       <th>ID
       <th>Data
       <th>Action
    """

    for i in range(len(dl)):
        r += f"""
         <tr>
          <td class="w">{i}
          <td class="w">{dl[i]}
          <td>
        """
        for action in actions:
            r += f"""
             <button name="a" value="{action}/{i}">{action}</button>
            """

    r += """
     </table>
    """
    return r
