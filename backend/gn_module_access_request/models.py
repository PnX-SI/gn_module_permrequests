from geonature.utils.env import DB
from geonature.core.gn_permissions.models import Permission
from pypnnomenclature.models import TNomenclatures as Nomenclature
from pypnusershub.db.models import User
from apptax.taxonomie.models import Taxref

from . import MODULE_CODE


SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"
PRIMARY_KEY = "id_access_request"

## ########################################################################
## Table de correspondance - cor_access_request_taxa
## ########################################################################
COR_ACCESS_REQUEST_TAXA_TABLE = DB.Table(
    f"cor_{MODULE_CODE.lower()}_taxa",
    DB.metadata,
    DB.Column(
        "id_access_request",
        DB.Integer,
        DB.ForeignKey(f"{SCHEMA_NAME}.{TABLE_NAME}.{PRIMARY_KEY}", ondelete="CASCADE"),
        primary_key=True,
    ),
    DB.Column(
        "cd_nom",
        DB.Integer,
        DB.ForeignKey("taxonomie.taxref.cd_nom"),
        primary_key=True,
    ),
    schema=SCHEMA_NAME,
)

## ########################################################################
## Table de correspondance - cor_access_request_permissions
## ########################################################################
COR_ACCESS_REQUEST_PERMISSIONS_TABLE = DB.Table(
    f"cor_{MODULE_CODE.lower()}_permissions",
    DB.metadata,
    DB.Column(
        "id_access_request",
        DB.Integer,
        DB.ForeignKey(f"{SCHEMA_NAME}.{TABLE_NAME}.{PRIMARY_KEY}", ondelete="CASCADE"),
        primary_key=True,
    ),
    DB.Column(
        "id_permission",
        DB.Integer,
        DB.ForeignKey("gn_permissions.t_permissions.id_permission", ondelete="CASCADE"),
        primary_key=True,
    ),
    schema=SCHEMA_NAME,
)


## ########################################################################
## Model Access Request
## ########################################################################
class AccessRequest(DB.Model):
    __tablename__ = TABLE_NAME
    __table_args__ = {"schema": SCHEMA_NAME}

    id_access_request = DB.Column(
        PRIMARY_KEY,
        DB.Integer,
        primary_key=True,
        autoincrement=True,
    )
    id_validation_status = DB.Column(
        DB.Integer,
        DB.ForeignKey(Nomenclature.id_nomenclature),
        nullable=True,
    )
    id_author = DB.Column(
        "id_author",
        DB.Integer,
        DB.ForeignKey("utilisateurs.t_roles.id_role"),
        nullable=False,
    )
    id_validator = DB.Column(
        "id_validator",
        DB.Integer,
        DB.ForeignKey("utilisateurs.t_roles.id_role"),
        nullable=True,
    )
    expiration_date = DB.Column(
        DB.Date,
        nullable=False,
    )
    description = DB.Column(DB.Text, nullable=True)

    validation_status = DB.relationship(
        Nomenclature,
        foreign_keys=[id_validation_status],
        lazy="joined",
    )
    author = DB.relationship(
        User,
        foreign_keys=[id_author],
        lazy="joined",
    )
    validator = DB.relationship(
        User,
        foreign_keys=[id_validator],
        lazy="joined",
    )
    taxa = DB.relationship(
        Taxref,
        secondary=COR_ACCESS_REQUEST_TAXA_TABLE,
        lazy="joined",
        backref="access_requests",
    )
    permissions = DB.relationship(
        Permission,
        secondary=COR_ACCESS_REQUEST_PERMISSIONS_TABLE,
        lazy="joined",
        backref="access_requests",
    )
