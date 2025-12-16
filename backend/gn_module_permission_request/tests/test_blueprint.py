from __future__ import annotations

from datetime import date, datetime, timedelta
from functools import lru_cache

import pytest
from sqlalchemy import select

from apptax.taxonomie.models import Taxref
from geonature.core.gn_commons.models import TModules
from geonature.core.gn_permissions.models import PermAction, PermObject, Permission
from geonature.utils.env import db
from gn_module_permission_request.models import PermissionRequest
from pypnusershub.tests.utils import logged_user
from ref_geo.models import LAreas, BibAreasTypes


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def taxon_ids():
    ids = db.session.scalars(select(Taxref.cd_nom).limit(5)).all()
    if len(ids) < 2:
        pytest.skip("Taxref table lacks enough records for tests")
    return ids


@pytest.fixture
def area_ids():
    stmt = (
        select(LAreas.id_area)
        .join(LAreas.area_type)
        .where(BibAreasTypes.type_code.in_(["COM", "DEP", "REG"]))
        .limit(5)
    )
    ids = db.session.scalars(stmt).all()
    if not ids:
        pytest.skip("Areas table lacks records with allowed types for tests")
    return ids


@lru_cache(maxsize=1)
def _permission_refs():
    module = db.session.scalar(select(TModules).filter_by(module_code="SYNTHESE"))
    if module is None:
        pytest.skip("Synthèse module is not available in the test database")
    read_action = db.session.scalar(select(PermAction).filter_by(code_action="R"))
    if read_action is None:
        pytest.skip("Missing read action in test database")
    object_all = db.session.scalar(select(PermObject).filter_by(code_object="ALL"))
    if object_all is None:
        pytest.skip("Missing ALL object in test database")
    return module.id_module, read_action.id_action, object_all.id_object


def _taxa_from_ids(cd_noms):
    return db.session.scalars(select(Taxref).where(Taxref.cd_nom.in_(cd_noms))).all()


def _areas_from_ids(ids):
    if not ids:
        return []
    areas = db.session.scalars(select(LAreas).where(LAreas.id_area.in_(ids))).all()
    areas_by_id = {area.id_area: area for area in areas}
    return [areas_by_id[area_id] for area_id in ids if area_id in areas_by_id]


def create_permission_request(
    author,
    *,
    description: str,
    initialization: date | None = None,
    expiration: date | None = None,
    validated: bool | None = None,
    sensitivity_filter: bool = True,
    taxa_ids: list[int] | None = None,
    areas_ids: list[int] | None = None,
    id_validator: int | None = None,
    validation_description: str | None = None,
):
    module_id, action_id, object_id = _permission_refs()
    if initialization is None:
        initialization = date.today()
    if expiration is None:
        expiration = initialization + timedelta(days=30)
    if taxa_ids is None:
        taxa_ids = db.session.scalars(select(Taxref.cd_nom).limit(2)).all()
    taxa = _taxa_from_ids(taxa_ids)
    if len(taxa) != len(taxa_ids):
        pytest.skip("Unable to resolve requested taxa identifiers")
    if areas_ids:
        areas = _areas_from_ids(areas_ids)
        if len(areas) != len(areas_ids):
            pytest.skip("Unable to resolve requested area identifiers")
    else:
        areas = []

    with db.session.begin_nested():
        permission = Permission(
            id_role=author.id_role,
            id_module=module_id,
            id_action=action_id,
            id_object=object_id,
            sensitivity_filter=sensitivity_filter,
            validated=validated,
        )
        permission.created_on = datetime.combine(initialization, datetime.min.time())
        permission.expire_on = datetime.combine(expiration, datetime.min.time())
        permission.taxons_filter = list(taxa)
        permission.areas_filter = list(areas)
        permission_request = PermissionRequest(
            id_author=author.id_role,
            id_validator=id_validator,
            description=description,
            validation_description=validation_description,
        )
        permission_request.permission = permission
        db.session.add(permission_request)
        db.session.flush()
        db.session.refresh(permission_request)
        return permission_request


def test_list_permission_requests_returns_latest(client, users, taxon_ids):
    author = users["admin_user"]
    first = create_permission_request(author, description="List request 1", taxa_ids=taxon_ids[:2])
    second = create_permission_request(
        author,
        description="List request 2",
        taxa_ids=taxon_ids[:2],
        expiration=date.today() + timedelta(days=45),
    )
    with logged_user(client, author):
        response = client.get(
            "/permission_request/",
            query_string={"orderby": "id_permission_request", "sort": "desc", "per_page": 5},
        )

    assert response.status_code == 200
    payload = response.get_json()
    ids = [item["id_permission_request"] for item in payload["items"]]
    assert second.id_permission_request == payload["items"][0]["id_permission_request"]
    assert first.id_permission_request in ids


def test_list_permission_requests_respects_scope(client, users, taxon_ids):
    other_request = create_permission_request(users["admin_user"], description="Hidden", taxa_ids=taxon_ids[:2])
    self_request = create_permission_request(users["self_user"], description="Visible", taxa_ids=taxon_ids[:2])

    with logged_user(client, users["self_user"]):
        response = client.get(
            "/permission_request/",
            query_string={"orderby": "id_permission_request", "sort": "desc", "per_page": 10},
        )

    assert response.status_code == 200
    ids = [item["id_permission_request"] for item in response.get_json()["items"]]
    assert self_request.id_permission_request in ids
    assert other_request.id_permission_request not in ids


def test_get_permission_request_returns_payload(client, users, taxon_ids, area_ids):
    created = create_permission_request(
        users["admin_user"],
        description="Fetch",
        taxa_ids=taxon_ids[:2],
        areas_ids=area_ids[:1],
    )

    with logged_user(client, users["admin_user"]):
        response = client.get(f"/permission_request/{created.id_permission_request}")

    assert response.status_code == 200
    data = response.get_json()
    assert data["id_permission_request"] == created.id_permission_request
    assert data["description"] == "Fetch"
    assert len(data["taxa"]) == len(taxon_ids[:2])
    assert [area["id_area"] for area in data["areas"]] == [area_ids[0]]


def test_get_permission_request_not_found(client, users):
    with logged_user(client, users["admin_user"]):
        response = client.get("/permission_request/-1")

    assert response.status_code == 404


def test_create_permission_request_success(client, users, taxon_ids, area_ids):
    initialization = date.today()
    expiration = initialization + timedelta(days=90)
    payload = {
        "description": "Created through API",
        "initialization_date": initialization.isoformat(),
        "expiration_date": expiration.isoformat(),
        "taxa": taxon_ids[:2],
        "sensitivity_filter": True,
        "areas": area_ids[:2],
    }

    with logged_user(client, users["admin_user"]):
        response = client.post("/permission_request/", json=payload)

    assert response.status_code == 201
    data = response.get_json()
    assert data["description"] == payload["description"]
    assert data["id_author"] == users["admin_user"].id_role
    created = db.session.get(PermissionRequest, data["id_permission_request"])
    assert created is not None
    assert created.permission is not None
    assert len(created.permission.taxons_filter) == len(taxon_ids[:2])
    assert sorted(area.id_area for area in created.permission.areas_filter) == sorted(area_ids[:2])


def test_create_permission_request_rejects_invalid_taxa(client, users):
    initialization = date.today()
    payload = {
        "description": "Invalid taxa",
        "initialization_date": initialization.isoformat(),
        "expiration_date": (initialization + timedelta(days=30)).isoformat(),
        "taxa": [999999999],
    }

    with logged_user(client, users["admin_user"]):
        response = client.post("/permission_request/", json=payload)

    assert response.status_code == 400


def test_create_permission_request_rejects_invalid_areas(client, users, taxon_ids):
    initialization = date.today()
    payload = {
        "description": "Invalid areas",
        "initialization_date": initialization.isoformat(),
        "expiration_date": (initialization + timedelta(days=30)).isoformat(),
        "taxa": taxon_ids[:2],
        "areas": [999999999],
    }

    with logged_user(client, users["admin_user"]):
        response = client.post("/permission_request/", json=payload)

    assert response.status_code == 400


def test_update_permission_request_updates_fields(client, users, taxon_ids, area_ids):
    created = create_permission_request(
        users["admin_user"],
        description="To update",
        taxa_ids=taxon_ids[:2],
        areas_ids=area_ids[:2],
    )
    new_expiration = date.today() + timedelta(days=150)
    update_payload = {
        "description": "Updated description",
        "sensitivity_filter": False,
        "taxa": [taxon_ids[1]],
        "expiration_date": new_expiration.isoformat(),
        "id_validator": users["admin_user"].id_role,
        "areas": [area_ids[1]],
    }

    with logged_user(client, users["admin_user"]):
        response = client.patch(f"/permission_request/{created.id_permission_request}", json=update_payload)

    assert response.status_code == 200
    data = response.get_json()
    assert data["description"] == update_payload["description"]
    reloaded = db.session.get(PermissionRequest, created.id_permission_request)
    assert reloaded.permission.sensitivity_filter is False
    assert [tax.cd_nom for tax in reloaded.permission.taxons_filter] == update_payload["taxa"]
    assert sorted(area.id_area for area in reloaded.permission.areas_filter) == sorted(update_payload["areas"])


def test_delete_permission_request_removes_entry(client, users, taxon_ids):
    created = create_permission_request(users["admin_user"], description="To delete", taxa_ids=taxon_ids[:2])

    with logged_user(client, users["admin_user"]):
        response = client.delete(f"/permission_request/{created.id_permission_request}")

    assert response.status_code == 204
    assert db.session.get(PermissionRequest, created.id_permission_request) is None


def test_update_validated_sets_validator(client, users, taxon_ids):
    created = create_permission_request(users["admin_user"], description="Needs validation", taxa_ids=taxon_ids[:2])

    with logged_user(client, users["admin_user"]):
        response = client.patch(
            f"/permission_request/{created.id_permission_request}/validated",
            json={"validated": True},
        )

    assert response.status_code == 200
    reloaded = db.session.get(PermissionRequest, created.id_permission_request)
    assert reloaded.validated is True
    assert reloaded.id_validator == users["admin_user"].id_role
    assert reloaded.validation_description is None
    assert reloaded.validation_date is not None


def test_update_validated_can_store_description(client, users, taxon_ids):
    created = create_permission_request(users["admin_user"], description="Needs message", taxa_ids=taxon_ids[:2])

    with logged_user(client, users["admin_user"]):
        response = client.patch(
            f"/permission_request/{created.id_permission_request}/validated",
            json={"validated": False, "validation_description": "Refus motivé"},
        )

    assert response.status_code == 200
    reloaded = db.session.get(PermissionRequest, created.id_permission_request)
    assert reloaded.validated is False
    assert reloaded.validation_description == "Refus motivé"
    first_validation_date = reloaded.validation_date
    assert first_validation_date is not None

    with logged_user(client, users["admin_user"]):
        response = client.patch(
            f"/permission_request/{created.id_permission_request}/validated",
            json={"validated": None},
        )

    assert response.status_code == 200
    reloaded = db.session.get(PermissionRequest, created.id_permission_request)
    assert reloaded.validated is None
    assert reloaded.validation_description is None
    assert reloaded.validation_date is not None
    assert reloaded.validation_date > first_validation_date


def test_update_validated_can_mark_in_progress_and_reset(client, users, taxon_ids):
    created = create_permission_request(
        users["admin_user"], description="Needs work", taxa_ids=taxon_ids[:2], id_validator=None
    )
    assert created.id_validator is None

    with logged_user(client, users["admin_user"]):
        response = client.patch(
            f"/permission_request/{created.id_permission_request}/validated",
            json={"validated": None},
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["validated"] is None
    assert data["id_validator"] == users["admin_user"].id_role
    assert data["status"] == "IN_PROGRESS"

    reloaded = db.session.get(PermissionRequest, created.id_permission_request)
    assert reloaded.id_validator == users["admin_user"].id_role

    with logged_user(client, users["admin_user"]):
        response = client.patch(
            f"/permission_request/{created.id_permission_request}/validated",
            json=None,
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["validated"] is None
    assert data["id_validator"] is None
    assert data["status"] == "PENDING"

    reloaded = db.session.get(PermissionRequest, created.id_permission_request)
    assert reloaded.id_validator is None
