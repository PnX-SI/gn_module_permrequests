"""
TOML schema specifications for module configuration parameters
"""

from marshmallow import Schema, fields, validate


class PermissionToCreateSchemaConf(Schema):
    module = fields.String(required=True)
    action = fields.String(
        required=True, validate=validate.OneOf(["R", "E", "C", "U", "D"])
    )


class SensitivityFilterConfigSchema(Schema):
    DISPLAY_ENABLED = fields.Boolean(load_default=False)
    DEFAULT_VALUE = fields.Boolean(load_default=True)


class TermsAcknowledgementSchemaConf(Schema):
    REQUIRED = fields.Boolean(load_default=True)
    URL = fields.String(load_default="https://www.google.fr")
    CLASS_CSS = fields.String(load_default="")


class PermrequestsConfigSchema(Schema):
    ALLOW_CUSTOM_AREA = fields.Boolean(load_default=False)
    ALLOWED_AREA_TYPE_CODES = fields.List(
        fields.String(),
        load_default=["COM", "DEP", "REG"],
    )
    ALLOWED_SCOPES = fields.List(
        fields.String(),
        load_default=["USER", "ORGANISM"],
    )
    PERMISSIONS_TO_CREATE = fields.List(
        fields.Nested(PermissionToCreateSchemaConf),
        load_default=[
            {"module": "SYNTHESE", "action": "R"},
            {"module": "SYNTHESE", "action": "E"},
        ],
    )
    SENSITIVITY_FILTER = fields.Nested(
        SensitivityFilterConfigSchema,
        load_default=SensitivityFilterConfigSchema().load({}),
    )
    TERMS_ACKNOWLEDGEMENT = fields.Nested(
        TermsAcknowledgementSchemaConf,
        load_default=TermsAcknowledgementSchemaConf().load({}),
    )

    # No use: all those with valdiation permissions are notified
    # List of id_role
    # NOTIFY_ON_NEW_REQUEST = fields.List(fields.Int, load_default=[])
