"""
Spécification du schéma toml des paramètres de configurations
"""

from geonature.utils.env import ROOT_DIR
from marshmallow import Schema, fields


class GnModuleSchemaConf(Schema):
    MODULE_URL = fields.String(load_default="/access_request")
