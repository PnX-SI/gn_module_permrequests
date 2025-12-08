"""Add validation_date to permission requests

Revision ID: c0c83e1f1f16
Revises: 743becffa102
Create Date: 2024-08-25 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "c0c83e1f1f16"
down_revision = "743becffa102"
depends_on = None

MODULE_CODE = "PERMISSION_REQUEST"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"


def upgrade():
    op.add_column(
        TABLE_NAME,
        sa.Column("validation_date", sa.DateTime(), nullable=True),
        schema=SCHEMA_NAME,
    )

    op.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA_NAME}.{TABLE_NAME} pr
            SET validation_date = NOW()
            FROM gn_permissions.t_permissions p
            WHERE pr.id_permission = p.id_permission
              AND p.validated IS NOT NULL
              AND pr.validation_date IS NULL
            """
        )
    )


def downgrade():
    op.drop_column(TABLE_NAME, "validation_date", schema=SCHEMA_NAME)
