"""Add file_name column to t_custom_area

Revision ID: 5e2f8c1a9b04
Revises: 37d854772600
Create Date: 2026-04-27 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

revision = "5e2f8c1a9b04"
down_revision = "37d854772600"
depends_on = None

MODULE_CODE = "PERMISSION_REQUEST"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
CUSTOM_AREA_TABLE = "t_custom_area"


def upgrade():
    op.execute(
        sa.text(
            f"ALTER TABLE {SCHEMA_NAME}.{CUSTOM_AREA_TABLE} ADD COLUMN file_name TEXT"
        )
    )


def downgrade():
    op.execute(
        sa.text(
            f"ALTER TABLE {SCHEMA_NAME}.{CUSTOM_AREA_TABLE} DROP COLUMN IF EXISTS file_name"
        )
    )
