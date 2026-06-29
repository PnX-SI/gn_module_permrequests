"""Add PERMREQUESTS area type to ref_geo.bib_areas_types

Revision ID: 7f3a1c8e0d92
Revises: 743becffa102
Create Date: 2026-04-27 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

from gn_module_permrequests import MODULE_CODE

revision = "7f3a1c8e0d92"
down_revision = "743becffa102"
depends_on = None

AREA_TYPE_CODE = MODULE_CODE.upper()
AREA_TYPE_NAME = "Zones des demandes de permission"
AREA_TYPE_DESC = "Zones géographiques personnalisées associées aux demandes de permission."


def upgrade():
    print(f"-> Inserting {AREA_TYPE_CODE} area type in ref_geo...")
    op.execute(
        sa.text(
            """
            INSERT INTO ref_geo.bib_areas_types (type_name, type_code, type_desc)
            VALUES (:type_name, :type_code, :type_desc)
            ON CONFLICT (type_code) DO NOTHING
            """
        ).bindparams(
            type_name=AREA_TYPE_NAME,
            type_code=AREA_TYPE_CODE,
            type_desc=AREA_TYPE_DESC,
        )
    )


def downgrade():
    print(f"-> Deleting links between areas of type {AREA_TYPE_CODE} and permissions...")
    op.execute(
        sa.text(
            """
            DELETE FROM gn_permissions.cor_permission_area WHERE id_area IN (
                SELECT id_area FROM ref_geo.l_areas WHERE id_type IN (
                    SELECT id_type FROM ref_geo.bib_areas_types WHERE type_code = :type_code
                )
            )
            """
        ).bindparams(type_code=AREA_TYPE_CODE)
    )

    print(f"-> Deleting areas of type {AREA_TYPE_CODE} from ref_geo...")
    op.execute(
        sa.text(
            """
            DELETE FROM ref_geo.l_areas WHERE id_type IN (
                SELECT id_type FROM ref_geo.bib_areas_types WHERE type_code = :type_code
            )
            """
        ).bindparams(type_code=AREA_TYPE_CODE)
    )

    print(f"-> Removing {AREA_TYPE_CODE} area type from ref_geo...")
    op.execute(
        sa.text(
            """
            DELETE FROM ref_geo.bib_areas_types WHERE type_code = :type_code
            """
        ).bindparams(type_code=AREA_TYPE_CODE)
    )
