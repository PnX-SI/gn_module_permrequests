"""
TOML schema specifications for module configuration parameters
"""

from marshmallow import Schema, fields


class TermsAcknowledgementSchemaConf(Schema):
    REQUIRED = fields.Boolean(load_default=True)
    URL = fields.String(load_default="https://www.google.fr")
    CLASS_CSS = fields.String(load_default="")

class SensitivityFilterConfigSchema(Schema):
    DISPLAY_ENABLED = fields.Boolean(load_default=False)
    DEFAULT_VALUE = fields.Boolean(load_default=True)

class PermrequestsConfigSchema(Schema):
    ALLOWED_SCOPES = fields.List(
        fields.String(),
        load_default=["USER", "ORGANISM"],
    )
    ALLOWED_AREA_TYPE_CODES = fields.List(
        fields.String(),
        load_default=["COM", "DEP", "REG"],
    )
    TERMS_ACKNOWLEDGEMENT = fields.Nested(
        TermsAcknowledgementSchemaConf,
        load_default=TermsAcknowledgementSchemaConf().load({}),
    )

    SENSITIVITY_FILTER = fields.Nested(
        SensitivityFilterConfigSchema,
        load_default=SensitivityFilterConfigSchema().load({}),
    )

    # No use: all those with valdiation permissions are notified
    # List of id_role
    # NOTIFY_ON_NEW_REQUEST = fields.List(fields.Int, load_default=[])
