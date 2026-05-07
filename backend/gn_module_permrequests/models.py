from datetime import datetime

from flask import g
import sqlalchemy as sa
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.dialects.postgresql import JSONB

from geonature.utils.env import DB
from geonature.core.gn_permissions.models import Permission
from pypnusershub.db.models import User
from utils_flask_sqla.models import qfilter

from . import MODULE_CODE


SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
SCOPE_USER = "USER"
SCOPE_ORGANISM = "ORGANISM"


class CustomArea(DB.Model):
    __tablename__ = "t_custom_areas"
    __table_args__ = {"schema": SCHEMA_NAME}

    id_custom_area = DB.Column(DB.Integer, primary_key=True, autoincrement=True)
    id_permission_request = DB.Column(
        "id_request",
        DB.Integer,
        DB.ForeignKey(f"{SCHEMA_NAME}.t_requests.id_request", ondelete="CASCADE"),
        nullable=True,
        unique=True,
    )
    geojson_data = DB.Column(JSONB, nullable=False)
    file_name = DB.Column(DB.Text, nullable=True)

    permission_request = DB.relationship(
        "PermissionRequest",
        back_populates="custom_area",
        uselist=False,
    )


cor_request_permission = DB.Table(
    "cor_request_permission",
    DB.Column(
        "id_request",
        DB.Integer,
        DB.ForeignKey(f"{SCHEMA_NAME}.t_requests.id_request", ondelete="CASCADE"),
        primary_key=True,
    ),
    DB.Column(
        "id_permission",
        DB.Integer,
        DB.ForeignKey(
            "gn_permissions.t_permissions.id_permission",
            ondelete="CASCADE",
        ),
        primary_key=True,
    ),
    schema=SCHEMA_NAME,
)


class PermissionRequest(DB.Model):
    __tablename__ = "t_requests"
    __table_args__ = {"schema": SCHEMA_NAME}

    id_permission_request = DB.Column(
        "id_request",
        DB.Integer,
        primary_key=True,
        autoincrement=True,
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
    validation_description = DB.Column(DB.Text, nullable=True)
    validation_date = DB.Column(DB.DateTime, nullable=True)
    description = DB.Column(DB.Text, nullable=True)

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
    permissions = DB.relationship(
        Permission,
        secondary=cor_request_permission,
        cascade="all, delete-orphan",
        single_parent=True,
        lazy="joined",
        order_by=Permission.id_permission,
        backref=DB.backref("permission_request", uselist=False),
    )
    custom_area = DB.relationship(
        CustomArea,
        foreign_keys=[CustomArea.id_permission_request],
        uselist=False,
        cascade="all, delete-orphan",
        lazy="joined",
        back_populates="permission_request",
    )

    @property
    def _ref_permission(self):
        return self.permissions[0] if self.permissions else None

    @classmethod
    def filter_by_scope(cls, scope, *, user=None):
        if user is None:
            user = g.current_user
        if scope == 0:
            return sa.false()
        elif scope == 1:
            return cls.permissions.any(Permission.role == user)
        elif scope == 2:
            return sa.or_(
                cls.permissions.any(Permission.role == user),
                cls.permissions.any(Permission.role.has(User.id_organisme == user.id_organisme)),
            )
        elif scope == 3:
            return sa.true()

    @qfilter(query=True)
    def filter_by_scope(cls, scope, *, query, user=None):
        if user is None:
            user = g.current_user
        if scope == 1:
            query = query.where(PermissionRequest.id_author == user.id_role)
        elif scope == 2:
            query = query.where(
                sa.or_(
                    PermissionRequest.id_author == user.id_role,
                    PermissionRequest.author.has(User.id_organisme == user.id_organisme),
                )
            )
        elif scope == 3:
            query = query.where(sa.true())
        else:
            query = query.where(sa.false())

        return query

    def has_instance_permission(self, scope, user=None):
        """
        Return True if the provided scope value grants permission to this permission request.
        Scope mapping follows the same logic as filter_by_scope:
            0 => no permission
            1 => author only
            2 => author or same organism (if any)
            3+ => full permission
        """
        if scope is None or scope <= 0:
            return False

        if scope >= 3:
            return True

        if user is None:
            user = g.current_user
        if user is None:
            return False

        if scope == 1:
            return self.id_author == user.id_role

        if scope == 2:
            if self.id_author == user.id_role:
                return True

            user_org = user.id_organisme
            author_org = self.author.id_organisme
            return author_org == user_org

        return False

    @hybrid_property
    def created_on(self):
        ref = self._ref_permission
        if ref is None or ref.created_on is None:
            return None
        return ref.created_on.date()

    @created_on.setter
    def created_on(self, value):
        if not self.permissions:
            raise AttributeError("No permission is linked to this permission request.")
        new_date = None
        if isinstance(value, datetime):
            new_date = value
        elif value is not None:
            new_date = datetime.combine(value, datetime.min.time())

        for p in self.permissions:
            p.created_on = new_date

    @created_on.expression
    def created_on(cls):
        return (
            sa.select(sa.func.date(Permission.created_on))
            .join(cor_request_permission)
            .where(cor_request_permission.c.id_request == cls.id_permission_request)
            .limit(1)
            .scalar_subquery()
        )

    @hybrid_property
    def expiration_date(self):
        ref = self._ref_permission
        if ref is None or ref.expire_on is None:
            return None
        return ref.expire_on.date()

    @expiration_date.setter
    def expiration_date(self, value):
        if not self.permissions:
            raise AttributeError("No permission is linked to this permission request.")
        new_date = None
        if isinstance(value, datetime):
            new_date = value
        elif value is not None:
            new_date = datetime.combine(value, datetime.min.time())

        for p in self.permissions:
            p.expire_on = new_date

    @expiration_date.expression
    def expiration_date(cls):
        return (
            sa.select(sa.func.date(Permission.expire_on))
            .join(cor_request_permission)
            .where(cor_request_permission.c.id_request == cls.id_permission_request)
            .limit(1)
            .scalar_subquery()
        )

    @hybrid_property
    def validated(self):
        ref = self._ref_permission
        if ref is None:
            return None
        return ref.validated

    @validated.setter
    def validated(self, value):
        if not self.permissions:
            raise AttributeError("No permission is linked to this permission request.")
        previous = self._ref_permission.validated if self._ref_permission else None
        if previous != value:
            self.validation_date = datetime.now()

        for p in self.permissions:
            p.validated = value

    @validated.expression
    def validated(cls):
        return (
            sa.select(Permission.validated)
            .join(cor_request_permission)
            .where(cor_request_permission.c.id_request == cls.id_permission_request)
            .limit(1)
            .scalar_subquery()
        )

    @property
    def scope(self):
        scope = None
        ref = self._ref_permission
        if ref is None or ref.id_role is None or self.id_author is None:
            scope = None
        elif ref.id_role == self.id_author:
            scope = SCOPE_USER
        else:
            role = ref.role
            author = self.author
            if (
                role is not None
                and role.groupe
                and author is not None
                and author.id_organisme is not None
                and role.id_organisme == author.id_organisme
            ):
                scope = SCOPE_ORGANISM

        return scope

    @hybrid_property
    def sensitivity_filter(self):
        ref = self._ref_permission
        if ref is None:
            return None
        return ref.sensitivity_filter

    @sensitivity_filter.setter
    def sensitivity_filter(self, value):
        if not self.permissions:
            raise AttributeError("No permission is linked to this permission request.")
        if value is None:
            raise ValueError("sensitivity_filter cannot be null.")

        for p in self.permissions:
            p.sensitivity_filter = bool(value)

    @sensitivity_filter.expression
    def sensitivity_filter(cls):
        return (
            sa.select(Permission.sensitivity_filter)
            .join(cor_request_permission)
            .where(cor_request_permission.c.id_request == cls.id_permission_request)
            .limit(1)
            .scalar_subquery()
        )

    @property
    def taxa(self):
        ref = self._ref_permission
        if ref is None:
            return []
        return ref.taxons_filter

    @taxa.setter
    def taxa(self, value):
        if not self.permissions:
            raise AttributeError("No permission is linked to this permission request.")

        for p in self.permissions:
            p.taxons_filter = value
