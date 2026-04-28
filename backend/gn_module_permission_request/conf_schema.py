"""
Spécification du schéma toml des paramètres de configurations
"""

from marshmallow import Schema, fields, validate


class TermsAcknowledgementSchemaConf(Schema):
    URL = fields.String(load_default="https://www.google.fr")


class PermissionToCreateSchemaConf(Schema):
    module = fields.String(required=True)
    action = fields.String(required=True, validate=validate.OneOf(["R", "E", "C", "U", "D"]))


class GnModuleSchemaConf(Schema):
    ALLOWED_SCOPES = fields.List(
        fields.String(),
        load_default=["USER", "ORGANISM"],
    )
    ALLOWED_AREA_TYPE_CODES = fields.List(
        fields.String(),
        load_default=["COM", "DEP", "REG"],
    )
    PERMISSIONS_TO_CREATE = fields.List(
        fields.Nested(PermissionToCreateSchemaConf),
        load_default=[
            {"module": "SYNTHESE", "action": "R"},
            {"module": "SYNTHESE", "action": "E"},
        ],
    )
    ALLOW_CUSTOM_AREA = fields.Boolean(load_default=False)
    REQUIRE_TERMS_ACKNOWLEDGEMENT = fields.Boolean(load_default=True)
    TERMS_ACKNOWLEDGEMENT = fields.Nested(
        TermsAcknowledgementSchemaConf,
        load_default=TermsAcknowledgementSchemaConf().load({}),
    )
    # No use: all those with valdiation permissions are notified
    # List of id_role
    # NOTIFY_ON_NEW_REQUEST = fields.List(fields.Int, load_default=[])
