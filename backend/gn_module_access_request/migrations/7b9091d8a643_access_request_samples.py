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
    permission_templates = conn.execute(
        sa.text(
            """
            SELECT pa.id_module, pa.id_object, pa.id_action
            FROM gn_permissions.t_permissions_available pa
            JOIN gn_commons.t_modules m ON m.id_module = pa.id_module
            WHERE m.module_code = :module_code
            """
        ),
        {"module_code": MODULE_CODE},
    ).fetchall()

    if not authors or not taxa_ids or not permission_templates:
        # Not enough data in reference tables to create demo content.
        return

    random.seed()

    today = date.today()
    preferred_validator = 3 if 3 in validators else (validators[0] if validators else None)

    for index in range(SAMPLE_REQUEST_COUNT):
        permission_sample_size = random.randint(
            MIN_PERMISSIONS_PER_REQUEST,
            MAX_PERMISSIONS_PER_REQUEST,
        )

        author_id = random.choice(authors)
        validator_id = random.choice(validators) if validators else None
        validated_value = None
        if preferred_validator is not None:
            if index % 10 == 0:
                validated_value = True
                validator_id = preferred_validator
            elif index % 10 == 1:
                validated_value = False
                validator_id = preferred_validator
        initialization_date = today - timedelta(days=random.randint(0, 30))
        expiration_date = initialization_date + timedelta(days=random.randint(30, 365))
        description = f"{DEMO_DESCRIPTION_PREFIX} {index + 1}"

        inserted_id = conn.execute(
            sa.text(
                f"""
                INSERT INTO {SCHEMA_NAME}.{TABLE_NAME} (
                    id_author,
                    id_validator,
                    initialization_date,
                    expiration_date,
                    description,
                    validated
                )
                VALUES (
                    :id_author,
                    :id_validator,
                    :initialization_date,
                    :expiration_date,
                    :description,
                    :validated
                )
                RETURNING {PRIMARY_KEY}
                """
            ),
            {
                "id_author": author_id,
                "id_validator": validator_id,
                "initialization_date": initialization_date,
                "expiration_date": expiration_date,
                "description": description,
                "validated": validated_value,
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

        for _ in range(permission_sample_size):
            permission_template = random.choice(permission_templates)
            permission_role_id = random.choice(authors)
            permission_id = conn.execute(
                sa.text(
                    """
                    INSERT INTO gn_permissions.t_permissions (
                        id_role,
                        id_action,
                        id_module,
                        id_object
                    )
                    VALUES (
                        :id_role,
                        :id_action,
                        :id_module,
                        :id_object
                    )
                    RETURNING id_permission
                    """
                ),
                {
                    "id_role": permission_role_id,
                    "id_action": permission_template.id_action,
                    "id_module": permission_template.id_module,
                    "id_object": permission_template.id_object,
                },
            ).scalar()

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
        permission_rows = conn.execute(
            sa.text(
                f"""
                SELECT id_permission
                FROM {SCHEMA_NAME}.{COR_ACCESS_REQUEST_PERMISSIONS_TABLE}
                WHERE id_access_request = :id_access_request
                """
            ),
            {"id_access_request": request_id},
        ).fetchall()
        for row in permission_rows:
            conn.execute(
                sa.text(
                    """
                    DELETE FROM gn_permissions.t_permissions
                    WHERE id_permission = :id_permission
                    """
                ),
                {"id_permission": row[0]},
            )
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
