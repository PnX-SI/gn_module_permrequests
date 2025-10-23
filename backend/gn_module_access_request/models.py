from geonature.utils.env import DB
from pypnnomenclature.models import TNomenclatures as Nomenclature

from . import MODULE_CODE


SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = MODULE_CODE.lower()
PRIMARY_KEY = f"id_{TABLE_NAME}"


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

    validation_status = DB.relationship(
        Nomenclature,
        foreign_keys=[id_validation_status],
        lazy="joined",
    )
