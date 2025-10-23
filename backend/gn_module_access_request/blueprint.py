"""
Définition des routes du module export
"""

import logging

from flask import (
    Blueprint,
    current_app,
)

LOGGER = current_app.logger
LOGGER.setLevel(logging.DEBUG)

blueprint = Blueprint("access_request", __name__, cli_group="access_request")

"""
#################################################################
    Commandes
#################################################################
"""
