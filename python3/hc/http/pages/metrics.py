"""
A simple set of metrics collection
"""

import hc.http.Pages
import time

from http import HTTPStatus


def add_routes(routes):
    """Add the default metrics page with its usual path"""
    routes["/metrics"] = Metrics()


def request_start(handler):
    handler.time_start = time.time()


def request_route(handler):
    handler.page.request += 1


def request_finish(handler):
    time_finish = time.time()
    elapsed = time_finish - handler.time_start
    try:
        if handler.page is not None:
            handler.page.elapsed += elapsed
    except AttributeError:
        pass


class Metrics(hc.http.Pages.Base):
    def do_GET(self, handler):
        d = []
        for route, page in handler.config.routes.items():
            d += [f'site_request_count{{route="{route}"}} {page.request}\n']
            d += [f'site_request_seconds{{route="{route}"}} {page.elapsed}\n']

        for route, page in handler.config.routes_subtree.items():
            d += [f'site_request_count{{route="{route}"}} {page.request}\n']
            d += [f'site_request_seconds{{route="{route}"}} {page.elapsed}\n']

        handler.send_page(HTTPStatus.OK, d, content_type="text/plain")
