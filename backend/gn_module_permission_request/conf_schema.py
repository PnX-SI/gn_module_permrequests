"""
Spécification du schéma toml des paramètres de configurations
"""

from marshmallow import Schema, fields


class GnModuleSchemaConf(Schema):
    REQUIRE_TERMS_ACKNOWLEDGEMENT = fields.Boolean(load_default=True)
    # No use: all those with valdiation permissions are notified
    # List of id_role
    # NOTIFY_ON_NEW_REQUEST = fields.List(fields.Int, load_default=[])
