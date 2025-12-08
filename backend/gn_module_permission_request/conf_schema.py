"""
Spécification du schéma toml des paramètres de configurations
"""

from marshmallow import Schema, fields

DEFAULT_TERMS_ACKNOWLEDGMENT = {"TEXT": "J'ai lu et j'accepte les conditions."}


class TermsAcknowledgmentSchema(Schema):
    TEXT = fields.String(load_default=DEFAULT_TERMS_ACKNOWLEDGMENT["TEXT"])


class GnModuleSchemaConf(Schema):
    REQUIRE_TERMS_ACKNOWLEDGEMENT = fields.Boolean(load_default=True)
    TERMS_ACKNOWLEDGMENT = fields.Nested(
        TermsAcknowledgmentSchema, load_default=DEFAULT_TERMS_ACKNOWLEDGMENT
    )
