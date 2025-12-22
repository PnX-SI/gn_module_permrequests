"""Make permission_request.id_permission non-nullable

Revision ID: ab3c0e7a2f1d
Revises: c0c83e1f1f16
Create Date: 2025-02-15 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "ab3c0e7a2f1d"
down_revision = "c0c83e1f1f16"
depends_on = None

MODULE_CODE = "PERMISSION_REQUEST"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"
FK_NAME = f"fk_{TABLE_NAME}_id_permission"


def upgrade():
    connection = op.get_bind()
    null_count = connection.execute(
        sa.text(f"SELECT COUNT(*) FROM {SCHEMA_NAME}.{TABLE_NAME} WHERE id_permission IS NULL")
    ).scalar()
    if null_count:
        raise RuntimeError(
            f"{SCHEMA_NAME}.{TABLE_NAME} contains {null_count} rows without permission. "
            "Clean them up before applying this migration."
        )

    op.drop_constraint(FK_NAME, TABLE_NAME, type_="foreignkey", schema=SCHEMA_NAME)
    op.alter_column(
        TABLE_NAME,
        "id_permission",
        existing_type=sa.Integer(),
        nullable=False,
        schema=SCHEMA_NAME,
    )
    op.create_foreign_key(
        FK_NAME,
        TABLE_NAME,
        "t_permissions",
        ["id_permission"],
        ["id_permission"],
        source_schema=SCHEMA_NAME,
        referent_schema="gn_permissions",
        ondelete="RESTRICT",
    )


def downgrade():
    op.drop_constraint(FK_NAME, TABLE_NAME, type_="foreignkey", schema=SCHEMA_NAME)
    op.alter_column(
        TABLE_NAME,
        "id_permission",
        existing_type=sa.Integer(),
        nullable=True,
        schema=SCHEMA_NAME,
    )
    op.create_foreign_key(
        FK_NAME,
        TABLE_NAME,
        "t_permissions",
        ["id_permission"],
        ["id_permission"],
        source_schema=SCHEMA_NAME,
        referent_schema="gn_permissions",
        ondelete="SET NULL",
    )
