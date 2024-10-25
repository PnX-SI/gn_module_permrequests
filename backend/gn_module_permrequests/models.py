from flask import g
import sqlalchemy as sa

from geonature.utils.env import db
from geonature.core.gn_permissions.models import Permission

from pypnusershub.db.models import User
from sqlalchemy.orm import backref
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.ext.mutable import MutableDict


class PermissionRequest(db.Model):
    __tablename__ = "t_permissions_requests"
    __table_args__ = {"schema": "gn_permissions"}

    id_permission = db.Column(
        db.Integer,
        db.ForeignKey(
            "gn_permissions.t_permissions.id_permission",
            onupdate="CASCADE",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )
    validated_on = db.Column(sa.DateTime)
    validated_by = db.Column(sa.Integer, sa.ForeignKey(column="utilisateurs.t_roles.id_role"))
    extras = db.Column(MutableDict.as_mutable(JSON), nullable=True)

    permission = db.relationship(
        Permission,
        backref=backref("request", cascade="save-update,merge,delete,delete-orphan"),
    )
    validator = db.relationship(User)

    def has_instance_permission(self, scope, *, user=None):
        if user is None:
            user = g.current_user
        if scope == 0:
            return False
        elif scope == 1:
            return self.permission.role == user
        elif scope == 2:
            return (
                self.permission.role == user
                or self.permission.role.id_organisme == user.id_organisme
            )
        elif scope == 3:
            return True

    @classmethod
    def filter_by_scope(cls, scope, *, user=None):
        if user is None:
            user = g.current_user
        if scope == 0:
            return sa.false()
        elif scope == 1:
            return cls.permission.has(Permission.role == user)
        elif scope == 2:
            return sa.or_(
                cls.permission.has(Permission.role == user),
                cls.permission.has(Permission.role.has(User.id_organisme == user.id_organisme)),
            )
        elif scope == 3:
            return sa.true()
