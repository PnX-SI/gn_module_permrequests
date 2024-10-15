from marshmallow import Schema, fields


class PermissionsRequestsConfigSchema(Schema):
    # List of id_role
    NOTIFY_ON_NEW_REQUEST = fields.List(fields.Int, load_default=[])
