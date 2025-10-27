from geonature.utils.env import DB
from geonature.core.gn_permissions.models import Permission
from pypnnomenclature.models import TNomenclatures as Nomenclature
from pypnusershub.db.models import User
from apptax.taxonomie.models import Taxref

from flask import g

import sqlalchemy as sa
from sqlalchemy import UniqueConstraint
from sqlalchemy.ext.associationproxy import association_proxy

from utils_flask_sqla.models import qfilter

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

COR_ACCESS_REQUEST_PERMISSIONS_TABLE_NAME = f"cor_{MODULE_CODE.lower()}_permissions"


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
    initialization_date = DB.Column(
        DB.Date,
        nullable=True,
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
    permission_links = DB.relationship(
        "AccessRequestPermission",
        cascade="all, delete-orphan",
        back_populates="access_request",
        lazy="joined",
    )
    permissions = association_proxy(
        "permission_links",
        "permission",
        creator=lambda permission: AccessRequestPermission(permission=permission),
    )

    @qfilter(query=True)
    def filter_by_scope(cls, scope, *, query, user=None):
        if user is None:
            user = g.current_user
        if scope == 1:
            query = query.where(AccessRequest.id_author == user.id_role)
        elif scope == 2:
            query = query.where(
                sa.or_(
                    AccessRequest.id_author == user.id_role,
                    AccessRequest.author.has(User.id_organisme == user.id_organisme),
                )
            )
        elif scope == 3:
            query = query.where(sa.true())
        else:
            query = query.where(sa.false())

        return query

    def has_instance_permission(self, scope, user=None):
        """
        Return True if the provided scope value grants access to this access request.
        Scope mapping follows the same logic as filter_by_scope:
            0 => no access
            1 => author only
            2 => author or same organism (if any)
            3+ => full access
        """
        if scope is None or scope <= 0:
            return False

        if scope >= 3:
            return True

        if user is None:
            user = getattr(g, "current_user", None)
        if user is None:
            return False

        if scope == 1:
            return self.id_author == getattr(user, "id_role", None)

        if scope == 2:
            if self.id_author == getattr(user, "id_role", None):
                return True

            user_org = getattr(user, "id_organisme", None)
            if user_org is None:
                return False

            author_org = getattr(self.author, "id_organisme", None) if self.author else None
            return author_org == user_org

        return False

## ########################################################################
## Association AccessRequest - Permission
## ########################################################################
class AccessRequestPermission(DB.Model):
    __tablename__ = COR_ACCESS_REQUEST_PERMISSIONS_TABLE_NAME
    __table_args__ = (UniqueConstraint("id_permission"), {"schema": SCHEMA_NAME})

    id_access_request = DB.Column(
        DB.Integer,
        DB.ForeignKey(f"{SCHEMA_NAME}.{TABLE_NAME}.{PRIMARY_KEY}", ondelete="CASCADE"),
        primary_key=True,
    )
    id_permission = DB.Column(
        DB.Integer,
        DB.ForeignKey("gn_permissions.t_permissions.id_permission", ondelete="CASCADE"),
        primary_key=True,
    )

    access_request = DB.relationship(
        "AccessRequest",
        back_populates="permission_links",
    )
    permission = DB.relationship(
        Permission,
        cascade="all, delete-orphan",
        single_parent=True,
        uselist=False,
        backref=DB.backref("access_request_permission_link", uselist=False),
    )
