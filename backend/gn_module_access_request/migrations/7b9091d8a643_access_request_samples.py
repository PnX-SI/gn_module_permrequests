"""Add demo access requests data

Revision ID: 7b9091d8a643
Revises: 743becffa102
Create Date: 2024-06-07 12:00:00.000000

"""

import random
from datetime import date, timedelta

from alembic import op
import sqlalchemy as sa

MODULE_CODE = "ACCESS_REQUEST"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"
PRIMARY_KEY = "id_access_request"
COR_ACCESS_REQUEST_TAXA_TABLE = f"cor_{MODULE_CODE.lower()}_taxa"
COR_ACCESS_REQUEST_PERMISSIONS_TABLE = f"cor_{MODULE_CODE.lower()}_permissions"
NOMENCLATURE_TYPE = f"{MODULE_CODE}_VALIDATION"
DEMO_DESCRIPTION_PREFIX = "Demande d'accès de démonstration"
SAMPLE_REQUEST_COUNT = 30
MIN_TAXA_PER_REQUEST = 1
MAX_TAXA_PER_REQUEST = 3
MIN_PERMISSIONS_PER_REQUEST = 1
MAX_PERMISSIONS_PER_REQUEST = 2


# revision identifiers, used by Alembic.
revision = "7b9091d8a643"
down_revision = None
branch_labels = ("access_request_samples",)
depends_on = "743becffa102"


def _fetch_ids(conn, query, params=None):
    result = conn.execute(sa.text(query), params or {})
    return [row[0] for row in result.fetchall()]


def upgrade():
    conn = op.get_bind()

    authors = _fetch_ids(
        conn,
        """
        SELECT id_role
        FROM utilisateurs.t_roles
        WHERE groupe = FALSE
        ORDER BY id_role
        LIMIT 50
        """,
    )
    validators = _fetch_ids(
        conn,
        """
        SELECT id_role
        FROM utilisateurs.t_roles
        WHERE groupe = FALSE
        ORDER BY id_role DESC
        LIMIT 50
        """,
    )
    taxa_ids = _fetch_ids(
        conn,
        """
        SELECT cd_nom
        FROM taxonomie.taxref
        WHERE cd_nom IS NOT NULL
        ORDER BY cd_nom
        LIMIT 200
        """,
    )
    status_ids = _fetch_ids(
        conn,
        """
        SELECT n.id_nomenclature
        FROM ref_nomenclatures.t_nomenclatures n
        JOIN ref_nomenclatures.bib_nomenclatures_types t ON t.id_type = n.id_type
        WHERE t.mnemonique = :mnemonique
        """,
        {"mnemonique": NOMENCLATURE_TYPE},
    )
    module_id_rows = conn.execute(
        sa.text(
            """
            SELECT id_module
            FROM gn_commons.t_modules
            WHERE module_code = :module_code
            """
        ),
        {"module_code": MODULE_CODE},
    ).fetchall()
    permission_ids = []
    if module_id_rows:
        module_id = module_id_rows[0][0]
        permission_ids = _fetch_ids(
            conn,
            """
            SELECT id_permission
            FROM gn_permissions.t_permissions
            WHERE id_module = :module_id
            """,
            {"module_id": module_id},
        )

    if not authors or not taxa_ids:
        # Not enough data in reference tables to create demo content.
        return

    today = date.today()
    random.seed()

    for index in range(SAMPLE_REQUEST_COUNT):
        author_id = random.choice(authors)
        validator_id = random.choice(validators) if validators else None
        validation_status_id = random.choice(status_ids) if status_ids else None
        expiration_date = today + timedelta(days=random.randint(30, 365))
        description = f"{DEMO_DESCRIPTION_PREFIX} {index + 1}"

        inserted_id = conn.execute(
            sa.text(
                f"""
                INSERT INTO {SCHEMA_NAME}.{TABLE_NAME} (
                    id_validation_status,
                    id_author,
                    id_validator,
                    expiration_date,
                    description
                )
                VALUES (
                    :id_validation_status,
                    :id_author,
                    :id_validator,
                    :expiration_date,
                    :description
                )
                RETURNING {PRIMARY_KEY}
                """
            ),
            {
                "id_validation_status": validation_status_id,
                "id_author": author_id,
                "id_validator": validator_id,
                "expiration_date": expiration_date,
                "description": description,
            },
        ).scalar()

        taxa_sample_size = random.randint(
            MIN_TAXA_PER_REQUEST, min(MAX_TAXA_PER_REQUEST, len(taxa_ids))
        )
        for cd_nom in random.sample(taxa_ids, taxa_sample_size):
            conn.execute(
                sa.text(
                    f"""
                    INSERT INTO {SCHEMA_NAME}.{COR_ACCESS_REQUEST_TAXA_TABLE} (
                        id_access_request,
                        cd_nom
                    )
                    VALUES (
                        :id_access_request,
                        :cd_nom
                    )
                    """
                ),
                {"id_access_request": inserted_id, "cd_nom": cd_nom},
            )

        if permission_ids:
            permission_sample_size = random.randint(
                MIN_PERMISSIONS_PER_REQUEST,
                min(MAX_PERMISSIONS_PER_REQUEST, len(permission_ids)),
            )
            for permission_id in random.sample(permission_ids, permission_sample_size):
                conn.execute(
                    sa.text(
                        f"""
                        INSERT INTO {SCHEMA_NAME}.{COR_ACCESS_REQUEST_PERMISSIONS_TABLE} (
                            id_access_request,
                            id_permission
                        )
                        VALUES (
                            :id_access_request,
                            :id_permission
                        )
                        """
                    ),
                    {"id_access_request": inserted_id, "id_permission": permission_id},
                )


def downgrade():
    conn = op.get_bind()

    request_rows = conn.execute(
        sa.text(
            f"""
            SELECT {PRIMARY_KEY}
            FROM {SCHEMA_NAME}.{TABLE_NAME}
            WHERE description LIKE :description_prefix
            """
        ),
        {"description_prefix": f"{DEMO_DESCRIPTION_PREFIX}%"},
    ).fetchall()

    request_ids = [row[0] for row in request_rows]

    for request_id in request_ids:
        conn.execute(
            sa.text(
                f"""
                DELETE FROM {SCHEMA_NAME}.{COR_ACCESS_REQUEST_PERMISSIONS_TABLE}
                WHERE id_access_request = :id_access_request
                """
            ),
            {"id_access_request": request_id},
        )
        conn.execute(
            sa.text(
                f"""
                DELETE FROM {SCHEMA_NAME}.{COR_ACCESS_REQUEST_TAXA_TABLE}
                WHERE id_access_request = :id_access_request
                """
            ),
            {"id_access_request": request_id},
        )
        conn.execute(
            sa.text(
                f"""
                DELETE FROM {SCHEMA_NAME}.{TABLE_NAME}
                WHERE {PRIMARY_KEY} = :id_access_request
                """
            ),
            {"id_access_request": request_id},
        )
