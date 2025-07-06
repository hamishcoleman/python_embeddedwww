from . import auth
from . import metrics


def add_routes(routes):
    """Add the default pages with their usual paths"""
    auth.add_routes(routes)
    metrics.add_routes(routes)
