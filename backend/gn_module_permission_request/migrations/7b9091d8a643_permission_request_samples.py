"""Add demo permission requests data

Revision ID: 7b9091d8a643
Revises: 743becffa102
Create Date: 2024-06-07 12:00:00.000000

"""

import random
from datetime import date, datetime, timedelta

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "7b9091d8a643"
down_revision = None
branch_labels = ("permission_request_samples",)
depends_on = "c0c83e1f1f16"

MODULE_CODE = "PERMISSION_REQUEST"
SYNTHESIS_MODULE_CODE = "SYNTHESE"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"
PRIMARY_KEY = "id_permission_request"

ORGANISM_NAME = "ar_sample__organisme"
ORGANISM_UUID = "9f3aa4ef-5cef-48ce-9d7a-c8456252ed5f"
ORGANISM_EMAIL = "ar.sample.organisme@example.test"
PASSWORD_HASH = "$2y$13$TMuRXgvIg6/aAez0lXLLFu0lyPk4m8N55NDhvLoUHh/Ar3rFzjFT."

USER_DEFINITIONS = [
    {
        "key": "requester_1",
        "identifiant": "ar_sample__demandeur_1",
        "nom_role": "Demandeur",
        "prenom_role": "Un",
        "email": "ar.sample.demandeur1@example.test",
    },
    {
        "key": "requester_2",
        "identifiant": "ar_sample__demandeur_2",
        "nom_role": "Demandeur",
        "prenom_role": "Deux",
        "email": "ar.sample.demandeur2@example.test",
    },
]

VALIDATOR_DEFINITIONS = [
    {
        "key": "validator_primary",
        "identifiant": "ar_sample__validateur",
        "nom_role": "Validateur",
        "prenom_role": "Principal",
        "email": "ar.sample.validateur@example.test",
    },
    {
        "key": "validator_secondary",
        "identifiant": "ar_sample__validateur_2",
        "nom_role": "Validateur",
        "prenom_role": "Secondaire",
        "email": "ar.sample.validateur2@example.test",
    },
]

GROUP_ROLE_DEFINITION = {
    "identifiant": "ar_sample__organisme_group",
    "nom_role": "Groupe ar_sample__organisme",
}

REQUESTER_SCOPE_MATRIX = {"C": 2, "R": 2, "U": 1, "D": 1}
VALIDATOR_SCOPE_MATRIX = {"C": None, "R": None, "U": None, "V": None, "D": None}

PERMISSION_REQUEST_DESCRIPTION_PREFIX = "ar_sample__permission_request_"
PERMISSION_REQUEST_TEMPLATES = [
    {"validated": None, "scope": "USER"},
    {"validated": True, "scope": "USER"},
    {"validated": False, "scope": "USER"},
    {"validated": None, "scope": "ORGANISM"},
    {"validated": True, "scope": "ORGANISM"},
    {"validated": False, "scope": "ORGANISM"},
]
PERMISSION_REQUEST_SAMPLE_SIZE = 54


def _get_module_id(conn, module_code):
    module_id = conn.execute(
        sa.text(
            """
            SELECT id_module
            FROM gn_commons.t_modules
            WHERE module_code = :module_code
            """
        ),
        {"module_code": module_code},
    ).scalar()
    if module_id is None:
        raise RuntimeError(f"Module '{module_code}' is not registered in gn_commons.t_modules.")
    return module_id


def _get_action_ids(conn, codes):
    codes = sorted(codes)
    placeholders = ", ".join(f":code_{idx}" for idx, _ in enumerate(codes))
    params = {f"code_{idx}": code for idx, code in enumerate(codes)}
    rows = conn.execute(
        sa.text(
            f"""
            SELECT code_action, id_action
            FROM gn_permissions.bib_actions
            WHERE code_action IN ({placeholders})
            """
        ),
        params,
    ).fetchall()
    action_map = {row[0]: row[1] for row in rows}
    missing = set(codes) - set(action_map.keys())
    if missing:
        raise RuntimeError(f"Missing permission actions: {', '.join(sorted(missing))}.")
    return action_map


def _get_object_id(conn, object_code):
    object_id = conn.execute(
        sa.text(
            """
            SELECT id_object
            FROM gn_permissions.t_objects
            WHERE code_object = :code
            """
        ),
        {"code": object_code},
    ).scalar()
    if object_id is None:
        raise RuntimeError(f"Permission object '{object_code}' is not available.")
    return object_id


def _ensure_sample_organism(conn):
    existing = conn.execute(
        sa.text(
            """
            SELECT id_organisme
            FROM utilisateurs.bib_organismes
            WHERE nom_organisme = :name
            """
        ),
        {"name": ORGANISM_NAME},
    ).scalar()
    if existing is not None:
        return existing

    return conn.execute(
        sa.text(
            """
            INSERT INTO utilisateurs.bib_organismes (
                nom_organisme,
                email_organisme,
                uuid_organisme
            ) VALUES (
                :name,
                :email,
                :uuid
            )
            RETURNING id_organisme
            """
        ),
        {"name": ORGANISM_NAME, "email": ORGANISM_EMAIL, "uuid": ORGANISM_UUID},
    ).scalar()


def _ensure_sample_user(conn, user_def, id_organisme):
    existing = conn.execute(
        sa.text(
            """
            SELECT id_role
            FROM utilisateurs.t_roles
            WHERE identifiant = :identifiant
            """
        ),
        {"identifiant": user_def["identifiant"]},
    ).scalar()
    if existing is not None:
        return existing

    return conn.execute(
        sa.text(
            """
            INSERT INTO utilisateurs.t_roles (
                groupe,
                identifiant,
                nom_role,
                prenom_role,
                email,
                id_organisme,
                pass_plus,
                date_insert
            ) VALUES (
                FALSE,
                :identifiant,
                :nom_role,
                :prenom_role,
                :email,
                :id_organisme,
                :pass_plus,
                now()
            )
            RETURNING id_role
            """
        ),
        {
            "identifiant": user_def["identifiant"],
            "nom_role": user_def["nom_role"],
            "prenom_role": user_def["prenom_role"],
            "email": user_def["email"],
            "id_organisme": id_organisme,
            "pass_plus": PASSWORD_HASH,
        },
    ).scalar()


def _ensure_group_role(conn, id_organisme):
    existing = conn.execute(
        sa.text(
            """
            SELECT id_role
            FROM utilisateurs.t_roles
            WHERE identifiant = :identifiant
            """
        ),
        {"identifiant": GROUP_ROLE_DEFINITION["identifiant"]},
    ).scalar()
    if existing is not None:
        return existing

    return conn.execute(
        sa.text(
            """
            INSERT INTO utilisateurs.t_roles (
                groupe,
                identifiant,
                nom_role,
                id_organisme,
                pass_plus,
                date_insert
            ) VALUES (
                TRUE,
                :identifiant,
                :nom_role,
                :id_organisme,
                :pass_plus,
                now()
            )
            RETURNING id_role
            """
        ),
        {
            "identifiant": GROUP_ROLE_DEFINITION["identifiant"],
            "nom_role": GROUP_ROLE_DEFINITION["nom_role"],
            "id_organisme": id_organisme,
            "pass_plus": PASSWORD_HASH,
        },
    ).scalar()


def _insert_permission(conn, payload):
    return conn.execute(
        sa.text(
            """
            INSERT INTO gn_permissions.t_permissions (
                id_role,
                id_action,
                id_module,
                id_object,
                scope_value,
                sensitivity_filter,
                created_on,
                expire_on,
                validated
            ) VALUES (
                :id_role,
                :id_action,
                :id_module,
                :id_object,
                :scope_value,
                :sensitivity_filter,
                :created_on,
                :expire_on,
                :validated
            )
            RETURNING id_permission
            """
        ),
        payload,
    ).scalar()


def _fetch_area_ids(conn, limit=10):
    rows = conn.execute(
        sa.text(
            """
            SELECT id_area
            FROM ref_geo.l_areas a
            JOIN ref_geo.bib_areas_types t ON t.id_type = a.id_type
            WHERE t.type_code IN ('COM', 'DEP', 'REG')
            ORDER BY a.id_area
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).fetchall()
    return [row[0] for row in rows]


def _fetch_taxa_ids(conn, limit=20):
    rows = conn.execute(
        sa.text(
            """
            SELECT cd_nom
            FROM taxonomie.taxref
            WHERE cd_nom IS NOT NULL
            ORDER BY cd_nom
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).fetchall()
    return [row[0] for row in rows]


def _assign_permission_filters(conn, permission_id, area_ids, taxon_ids):
    area_k = min(len(area_ids), max(1, random.randint(1, 3)))
    taxon_k = min(len(taxon_ids), max(1, random.randint(1, 3)))
    area_sample = random.sample(area_ids, k=area_k)
    taxon_sample = random.sample(taxon_ids, k=taxon_k)

    for id_area in area_sample:
        conn.execute(
            sa.text(
                """
                INSERT INTO gn_permissions.cor_permission_area (id_permission, id_area)
                VALUES (:id_permission, :id_area)
                """
            ),
            {"id_permission": permission_id, "id_area": id_area},
        )

    for cd_nom in taxon_sample:
        conn.execute(
            sa.text(
                """
                INSERT INTO gn_permissions.cor_permission_taxref (id_permission, cd_nom)
                VALUES (:id_permission, :cd_nom)
                """
            ),
            {"id_permission": permission_id, "cd_nom": cd_nom},
        )


def _grant_module_permissions(conn, module_id, object_id, action_ids, role_id, scope_matrix):
    for action_code, scope_value in scope_matrix.items():
        payload = {
            "id_role": role_id,
            "id_action": action_ids[action_code],
            "id_module": module_id,
            "id_object": object_id,
            "scope_value": scope_value,
            "sensitivity_filter": False,
            "created_on": datetime.now(),
            "expire_on": None,
            "validated": True,
        }
        _insert_permission(conn, payload)


def _create_permission_request_permissions(
    conn,
    authors,
    validator_ids,
    group_role_id,
    read_action_id,
    synthese_module_id,
    object_id,
    area_ids,
    taxon_ids,
):
    if not area_ids:
        raise RuntimeError("Unable to create sample permission requests without geographic areas.")
    if not taxon_ids:
        raise RuntimeError("Unable to create sample permission requests without taxa.")

    random.seed(42)
    base_date = date.today()
    template_count = len(PERMISSION_REQUEST_TEMPLATES)
    for index in range(PERMISSION_REQUEST_SAMPLE_SIZE):
        template = PERMISSION_REQUEST_TEMPLATES[index % template_count]
        id_author = random.choice(authors)
        created_on_date = base_date - timedelta(days=random.randint(-40, 40))
        expiration = created_on_date + timedelta(days=random.randint(1, 40))
        created_on = datetime.combine(created_on_date, datetime.min.time())
        expire_on = datetime.combine(expiration, datetime.min.time())
        scope_value = template["scope"]
        validated_value = template["validated"]
        validator = random.choice(validator_ids) if validated_value is not None else None
        permission_role_id = group_role_id if scope_value == "ORGANISM" else id_author
        permission_id = _insert_permission(
            conn,
            {
                "id_role": permission_role_id,
                "id_action": read_action_id,
                "id_module": synthese_module_id,
                "id_object": object_id,
                "scope_value": None,
                "sensitivity_filter": random.choice([True, False]),
                "created_on": created_on,
                "expire_on": expire_on,
                "validated": validated_value,
            },
        )
        _assign_permission_filters(conn, permission_id, area_ids, taxon_ids)

        conn.execute(
            sa.text(
                f"""
                INSERT INTO {SCHEMA_NAME}.{TABLE_NAME} (
                    id_author,
                    id_validator,
                    validation_description,
                    description,
                    id_permission
                ) VALUES (
                    :id_author,
                    :id_validator,
                    :validation_description,
                    :description,
                    :id_permission
                )
                """
            ),
            {
                "id_author": id_author,
                "id_validator": validator,
                "validation_description": (
                    f"Commentaire de validation #{index + 1}"
                    if validator is not None and random.random() < 0.5
                    else None
                ),
                "description": f"{PERMISSION_REQUEST_DESCRIPTION_PREFIX}{index + 1}",
                "id_permission": permission_id,
            },
        )


def upgrade():
    conn = op.get_bind()
    module_id = _get_module_id(conn, MODULE_CODE)
    synthese_module_id = _get_module_id(conn, SYNTHESIS_MODULE_CODE)
    object_id = _get_object_id(conn, "ALL")
    module_action_ids = _get_action_ids(
        conn,
        set(REQUESTER_SCOPE_MATRIX.keys()) | set(VALIDATOR_SCOPE_MATRIX.keys()),
    )
    synthesis_read_action_id = _get_action_ids(conn, {"R"})["R"]

    organism_id = _ensure_sample_organism(conn)

    requester_ids = [
        _ensure_sample_user(conn, definition, organism_id) for definition in USER_DEFINITIONS
    ]
    validator_ids = [
        _ensure_sample_user(conn, definition, organism_id) for definition in VALIDATOR_DEFINITIONS
    ]
    group_role_id = _ensure_group_role(conn, organism_id)

    area_ids = _fetch_area_ids(conn, limit=20)
    taxon_ids = _fetch_taxa_ids(conn, limit=40)
    if not area_ids:
        raise RuntimeError("Unable to fetch reference areas for sample permission requests.")
    if not taxon_ids:
        raise RuntimeError("Unable to fetch reference taxa for sample permission requests.")

    for requester_id in requester_ids:
        _grant_module_permissions(
            conn,
            module_id,
            object_id,
            module_action_ids,
            requester_id,
            REQUESTER_SCOPE_MATRIX,
        )
    for validator_id in validator_ids:
        _grant_module_permissions(
            conn,
            module_id,
            object_id,
            module_action_ids,
            validator_id,
            VALIDATOR_SCOPE_MATRIX,
        )

    _create_permission_request_permissions(
        conn,
        requester_ids,
        validator_ids,
        group_role_id,
        synthesis_read_action_id,
        synthese_module_id,
        object_id,
        area_ids,
        taxon_ids,
    )


def _delete_permission_ids(conn, permission_ids):
    for permission_id in permission_ids:
        conn.execute(
            sa.text(
                """
                DELETE FROM gn_permissions.cor_permission_area
                WHERE id_permission = :id_permission
                """
            ),
            {"id_permission": permission_id},
        )
        conn.execute(
            sa.text(
                """
                DELETE FROM gn_permissions.cor_permission_taxref
                WHERE id_permission = :id_permission
                """
            ),
            {"id_permission": permission_id},
        )
        conn.execute(
            sa.text(
                """
                DELETE FROM gn_permissions.t_permissions
                WHERE id_permission = :id_permission
                """
            ),
            {"id_permission": permission_id},
        )


def _fetch_sample_role_ids(conn):
    identifiers = [definition["identifiant"] for definition in USER_DEFINITIONS]
    identifiers.extend(definition["identifiant"] for definition in VALIDATOR_DEFINITIONS)
    identifiers.append(GROUP_ROLE_DEFINITION["identifiant"])
    role_ids = {}
    for ident in identifiers:
        role_id = conn.execute(
            sa.text(
                """
                SELECT id_role
                FROM utilisateurs.t_roles
                WHERE identifiant = :identifiant
                """
            ),
            {"identifiant": ident},
        ).scalar()
        if role_id is not None:
            role_ids[ident] = role_id
    return role_ids


def _cleanup_permission_requests(conn):
    rows = (
        conn.execute(
            sa.text(
                f"""
            SELECT {PRIMARY_KEY} AS id_permission_request, id_permission
            FROM {SCHEMA_NAME}.{TABLE_NAME}
            WHERE description LIKE :prefix
            """
            ),
            {"prefix": f"{PERMISSION_REQUEST_DESCRIPTION_PREFIX}%"},
        )
        .mappings()
        .all()
    )
    permission_ids = [row["id_permission"] for row in rows if row["id_permission"] is not None]

    for row in rows:
        conn.execute(
            sa.text(
                f"""
                DELETE FROM {SCHEMA_NAME}.{TABLE_NAME}
                WHERE {PRIMARY_KEY} = :id_permission_request
                """
            ),
            {"id_permission_request": row["id_permission_request"]},
        )

    if permission_ids:
        _delete_permission_ids(conn, permission_ids)


def _cleanup_module_permissions(conn, role_ids):
    if not role_ids:
        return
    module_id = conn.execute(
        sa.text(
            """
            SELECT id_module
            FROM gn_commons.t_modules
            WHERE module_code = :module_code
            """
        ),
        {"module_code": MODULE_CODE},
    ).scalar()
    if module_id is None:
        return

    for role_id in role_ids.values():
        permission_rows = conn.execute(
            sa.text(
                """
                SELECT id_permission
                FROM gn_permissions.t_permissions
                WHERE id_role = :id_role
                  AND id_module = :id_module
                """
            ),
            {"id_role": role_id, "id_module": module_id},
        ).scalars()
        permission_ids = list(permission_rows)
        if permission_ids:
            _delete_permission_ids(conn, permission_ids)


def _delete_sample_roles(conn, role_ids):
    for role_id in role_ids.values():
        conn.execute(
            sa.text(
                """
                DELETE FROM utilisateurs.t_roles
                WHERE id_role = :id_role
                """
            ),
            {"id_role": role_id},
        )


def _delete_sample_organism(conn):
    conn.execute(
        sa.text(
            """
            DELETE FROM utilisateurs.bib_organismes o
            WHERE o.nom_organisme = :name
              AND NOT EXISTS (
                  SELECT 1
                  FROM utilisateurs.t_roles r
                  WHERE r.id_organisme = o.id_organisme
              )
            """
        ),
        {"name": ORGANISM_NAME},
    )


def downgrade():
    conn = op.get_bind()
    _cleanup_permission_requests(conn)
    role_ids = _fetch_sample_role_ids(conn)
    sample_role_values = [role_id for role_id in role_ids.values() if role_id is not None]
    if sample_role_values:
        conn.execute(
            sa.text(
                """
                DELETE FROM gn_notifications.t_notifications
                WHERE id_role = ANY(:role_ids)
                """
            ),
            {"role_ids": sample_role_values},
        )
    _cleanup_module_permissions(conn, role_ids)
    _delete_sample_roles(conn, role_ids)
    _delete_sample_organism(conn)
