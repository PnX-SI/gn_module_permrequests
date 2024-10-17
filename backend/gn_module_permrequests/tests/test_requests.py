from copy import deepcopy
from datetime import datetime, timedelta

import pytest
from flask import url_for
import sqlalchemy as sa
from werkzeug import Client
from werkzeug.exceptions import BadRequest, Forbidden, Unauthorized, Conflict

from geonature.utils.env import db
from geonature.core.gn_permissions.models import PermAction, PermObject
from geonature.tests.utils import set_logged_user

from apptax.taxonomie.models import Taxref
from ref_geo.models import LAreas

from gn_module_permrequests.models import PermissionRequest


def req_ids(reqs) -> set:
    return {req.id_permission for req in reqs}


@pytest.mark.usefixtures("client_class", "temporary_transaction")
class TestRequests:
    client: Client

    def test_list_requests(self, users, requests):
        url = url_for(endpoint="permissions_requests.list_requests")

        r = self.client.get(url)
        assert r.status_code == Unauthorized.code, r.data

        set_logged_user(self.client, users["noright_user"])
        r = self.client.get(url)
        assert r.status_code == Forbidden.code, r.data

        set_logged_user(self.client, users["self_user"])
        r = self.client.get(url)
        assert r.status_code == 200, r.data
        resp_ids = {req["id_permission"] for req in r.json}
        expected_ids = {requests[req].id_permission for req in ["r2"]}
        unexpected_ids = {requests[req].id_permission for req in ["r1", "r3"]}
        assert expected_ids <= resp_ids
        assert not unexpected_ids & resp_ids

        set_logged_user(self.client, users["associate_user"])
        r = self.client.get(url)
        assert r.status_code == 200, r.data
        resp_ids = {req["id_permission"] for req in r.json}
        expected_ids = {requests[req].id_permission for req in ["r1", "r2"]}
        unexpected_ids = {requests[req].id_permission for req in ["r3"]}
        assert expected_ids <= resp_ids
        assert not unexpected_ids & resp_ids

        set_logged_user(self.client, users["admin_user"])
        r = self.client.get(url)
        assert r.status_code == 200, r.data
        resp_ids = {req["id_permission"] for req in r.json}
        expected_ids = {requests[req].id_permission for req in ["r1", "r2", "r3"]}
        assert expected_ids <= resp_ids

    def test_get_request(self, users, requests):
        def get_url(r):
            return url_for(
                "permissions_requests.get_request",
                id_permission=requests[r].id_permission,
            )

        r = self.client.get(get_url("r1"))
        assert r.status_code == Unauthorized.code, r.data

        set_logged_user(self.client, users["noright_user"])
        r = self.client.get(get_url("r1"))
        assert r.status_code == Forbidden.code, r.data

        set_logged_user(self.client, users["self_user"])
        r = self.client.get(get_url("r1"))
        assert r.status_code == Forbidden.code, r.data

        r = self.client.get(get_url("r2"))
        assert r.status_code == 200, r.data

        set_logged_user(self.client, users["associate_user"])
        r = self.client.get(get_url("r2"))
        assert r.status_code == 200, r.data
        r = self.client.get(get_url("r3"))
        assert r.status_code == Forbidden.code, r.data

        set_logged_user(self.client, users["admin_user"])
        r = self.client.get(get_url("r3"))
        assert r.status_code == 200, r.data
        assert type(r.json) is dict
        assert {"id_permission", "permission"} <= r.json.keys()
        assert r.json["id_permission"] == requests["r3"].id_permission

    def test_create_request(self, users, modules):
        url = url_for("permissions_requests.create_request")
        id_action_read = db.session.execute(
            sa.select(PermAction.id_action).where(PermAction.code_action == "R")
        ).scalar_one()
        id_object_all = db.session.execute(
            sa.select(PermObject.id_object).where(PermObject.code_object == "ALL")
        ).scalar_one()
        id_area = db.session.execute(
            sa.select(LAreas.id_area).where(LAreas.area_name == "Gap")
        ).scalar_one()
        cd_nom = db.session.execute(
            sa.select(Taxref.cd_nom).where(Taxref.cd_nom == 2852)
        ).scalar_one()
        data = {
            "permission": {
                "id_role": users["user"].id_role,
                "id_action": id_action_read,
                "id_module": modules["a"].id_module,
                "id_object": id_object_all,
                "scope_value": 2,
                "sensitivity_filter": True,
                "areas_filter": [{"id_area": id_area}],
                "taxons_filter": [{"cd_nom": cd_nom}],
            },
        }

        r = self.client.put(url, data=data)
        assert r.status_code == Unauthorized.code, r.data

        set_logged_user(self.client, users["noright_user"])
        r = self.client.put(url, data=data)
        assert r.status_code == Forbidden.code, r.data
        assert "no permissions to C" in r.json["description"]

        # self user has scope 1 so can only add requests for himself
        set_logged_user(self.client, users["self_user"])
        r = self.client.put(url, data=data)
        assert r.status_code == Forbidden.code, r.data
        assert "for this user" in r.json["description"]

        set_logged_user(self.client, users["user"])
        _data = deepcopy(data)
        _data["permission"]["id_role"] = -1
        r = self.client.put(url, data=_data)
        assert r.status_code == BadRequest.code, r.data
        assert "role not found" in r.json["description"].lower()

        _data = deepcopy(data)
        _data["permission"]["id_action"] = -1
        r = self.client.put(url, data=_data)
        assert r.status_code == BadRequest.code, r.data
        assert "action not found" in r.json["description"].lower()

        _data = deepcopy(data)
        _data["permission"]["id_module"] = -1
        r = self.client.put(url, data=_data)
        assert r.status_code == BadRequest.code, r.data
        assert "module not found" in r.json["description"].lower()

        _data = deepcopy(data)
        _data["permission"]["id_object"] = -1
        r = self.client.put(url, data=_data)
        assert r.status_code == BadRequest.code, r.data
        assert "object not found" in r.json["description"].lower()

        _data = deepcopy(data)
        _data["permission"]["scope_value"] = 5
        r = self.client.put(url, data=_data)
        assert r.status_code == BadRequest.code, r.data
        assert "scope_value" in r.json["description"].lower()

        _data = deepcopy(data)
        _data["permission"]["areas_filter"] = [{"id_area": id_area}, {"id_area": -42}]
        r = self.client.put(url, data=_data)
        assert r.status_code == BadRequest.code, r.data
        assert "areas_filter" in r.json["description"].lower()

        _data = deepcopy(data)
        _data["permission"]["taxons_filter"] = [{"cd_nom": -42}, {"cd_nom": cd_nom}]
        r = self.client.put(url, data=_data)
        assert r.status_code == BadRequest.code, r.data
        assert "taxons_filter" in r.json["description"].lower()

        r = self.client.put(url, data=data)
        assert r.status_code == 200, r.data
        perm_req = db.session.execute(
            sa.select(PermissionRequest).where(
                PermissionRequest.id_permission == r.json["id_permission"]
            )
        ).scalar_one()
        assert perm_req.permission.validated is None
        assert perm_req.permission.role == users["user"]

        # Try creating request without expliciting permission role
        _data = deepcopy(data)
        _data["permission"].pop("id_role")
        r = self.client.put(url, data=_data)
        assert r.status_code == 200, r.data
        perm_req = db.session.execute(
            sa.select(PermissionRequest).where(
                PermissionRequest.id_permission == r.json["id_permission"]
            )
        ).scalar_one()
        assert perm_req.permission.validated is None
        assert perm_req.permission.role == users["user"]

    def test_update_request(self, users, modules, requests):
        perm_req = requests["r1"]
        url = url_for("permissions_requests.update_request", id_permission=perm_req.id_permission)

        r = self.client.post(url, data={})
        assert r.status_code == Unauthorized.code, r.data

        set_logged_user(self.client, users["noright_user"])
        r = self.client.post(url, data={})
        assert r.status_code == Forbidden.code, r.data

        set_logged_user(self.client, users["self_user"])
        r = self.client.post(url, data={})
        assert r.status_code == Forbidden.code, r.data

        set_logged_user(self.client, users["user"])
        r = self.client.post(url, data={})
        assert r.status_code == 200, r.data

        r = self.client.post(url, data={"permission": {}})
        assert r.status_code == BadRequest.code, r.data

        r = self.client.post(
            url, data={"permission": {"id_permission": requests["r2"].id_permission}}
        )
        assert r.status_code == BadRequest.code, r.data

        r = self.client.post(url, data={"permission": {"id_permission": perm_req.id_permission}})
        assert r.status_code == 200, r.data

        r = self.client.post(
            url,
            data={"permission": {"id_permission": perm_req.id_permission, "id_role": -1}},
        )
        assert r.status_code == BadRequest.code, r.data
        assert "role not found" in r.json["description"].lower()

        r = self.client.post(
            url,
            data={
                "permission": {
                    "id_permission": perm_req.id_permission,
                    "id_role": users["stranger_user"].id_role,
                }
            },
        )
        assert r.status_code == Forbidden.code, r.data
        assert perm_req.permission.role == users["user"]  # not changed

        r = self.client.post(
            url,
            data={"permission": {"id_permission": perm_req.id_permission, "id_action": -1}},
        )
        assert r.status_code == BadRequest.code, r.data
        assert "action not found" in r.json["description"].lower()
        assert perm_req.permission.action.code_action == "C"  # not changed

        id_action_update = db.session.execute(
            sa.select(PermAction.id_action).where(PermAction.code_action == "U")
        ).scalar()
        r = self.client.post(
            url,
            data={
                "permission": {
                    "id_permission": perm_req.id_permission,
                    "id_action": id_action_update,
                }
            },
        )
        assert r.status_code == 200, r.data
        assert perm_req.permission.action.code_action == "U"

        r = self.client.post(
            url,
            data={"permission": {"id_permission": perm_req.id_permission, "id_module": -1}},
        )
        assert r.status_code == BadRequest.code, r.data
        assert "module not found" in r.json["description"].lower()
        assert perm_req.permission.module == modules["a"]  # not changed

        r = self.client.post(
            url,
            data={
                "permission": {
                    "id_permission": perm_req.id_permission,
                    "id_module": modules["b"].id_module,
                }
            },
        )
        assert r.status_code == 200, r.data
        assert perm_req.permission.module == modules["b"]

        r = self.client.post(
            url,
            data={"permission": {"id_permission": perm_req.id_permission, "id_object": -1}},
        )
        assert r.status_code == BadRequest.code, r.data
        assert "object not found" in r.json["description"].lower()

        r = self.client.post(
            url,
            data={
                "permission": {
                    "id_permission": perm_req.id_permission,
                    "areas_filter": [{"id_area": -1}],
                }
            },
        )
        assert r.status_code == BadRequest.code, r.data
        assert "areas_filter" in r.json["description"].lower()
        assert perm_req.permission.areas_filter == []

        id_area = db.session.execute(
            sa.select(LAreas.id_area).where(LAreas.area_name == "Gap")
        ).scalar_one()
        r = self.client.post(
            url,
            data={
                "permission": {
                    "id_permission": perm_req.id_permission,
                    "areas_filter": [{"id_area": id_area}],
                }
            },
        )
        assert r.status_code == 200, r.data
        assert {area.id_area for area in perm_req.permission.areas_filter} == {id_area}

        r = self.client.post(
            url,
            data={
                "permission": {
                    "id_permission": perm_req.id_permission,
                    "taxons_filter": [{"cd_nom": -1}],
                }
            },
        )
        assert r.status_code == BadRequest.code, r.data
        assert "taxons_filter" in r.json["description"].lower()
        assert perm_req.permission.taxons_filter == []

        cd_nom = db.session.execute(
            sa.select(Taxref.cd_nom).where(Taxref.cd_nom == 2852)
        ).scalar_one()
        r = self.client.post(
            url,
            data={
                "permission": {
                    "id_permission": perm_req.id_permission,
                    "taxons_filter": [{"cd_nom": cd_nom}],
                }
            },
        )
        assert r.status_code == 200, r.data
        assert {taxon.cd_nom for taxon in perm_req.permission.taxons_filter} == {cd_nom}

        r = self.client.post(
            url,
            data={
                "permission": {
                    "id_permission": perm_req.id_permission,
                },
                "extras": {"field1": "value2"},
            },
        )
        assert r.status_code == 200, r.data
        assert perm_req.extras == {"field1": "value2"}

    def test_update_request_validated(self, users, modules, requests):
        perm_req = requests["r1"]
        with db.session.begin_nested():
            perm_req.permission.validated = True
            perm_req.permission.scope_value = 1
        url = url_for("permissions_requests.update_request", id_permission=perm_req.id_permission)

        set_logged_user(self.client, users["user"])
        r = self.client.post(
            url,
            data={
                "permission": {
                    "id_permission": perm_req.id_permission,
                    "scope_value": 2,
                },
            },
        )
        assert r.status_code == Forbidden.code, r.data
        assert perm_req.permission.scope_value == 1

        set_logged_user(self.client, users["admin_user"])
        r = self.client.post(
            url,
            data={
                "permission": {
                    "id_permission": perm_req.id_permission,
                    "scope_value": 2,
                },
            },
        )
        assert r.status_code == 200, r.data
        assert perm_req.permission.scope_value == 2

    def test_validate_request(self, users, requests):
        url = url_for(
            "permissions_requests.validate_request",
            id_permission=requests["r1"].id_permission,
        )

        r = self.client.post(url, data={})
        assert r.status_code == Unauthorized.code, r.data

        set_logged_user(self.client, users["noright_user"])
        r = self.client.post(url, data={})
        assert r.status_code == Forbidden.code, r.data

        set_logged_user(self.client, users["admin_user"])
        r = self.client.post(url, data={})
        assert r.status_code == BadRequest.code, r.data

        r = self.client.post(url, data={"validated": None})
        assert r.status_code == Conflict.code, r.data
        assert requests["r1"].permission.validated is None

        r = self.client.post(url, data={"validated": False})
        assert r.status_code == 200, r.data
        assert requests["r1"].permission.validated is False
        assert requests["r1"].validated_by == users["admin_user"].id_role
        assert requests["r1"].validated_on >= datetime.now() - timedelta(seconds=1)

        r = self.client.post(url, data={"validated": True})
        assert r.status_code == 200, r.data
        assert requests["r1"].permission.validated is True

        r = self.client.post(url, data={"validated": None})
        assert r.status_code == 200, r.data
        assert requests["r1"].permission.validated is None

    def test_delete_request(self, users, requests):
        url = url_for(
            "permissions_requests.delete_request",
            id_permission=requests["r1"].id_permission,
        )

        r = self.client.delete(url)
        assert r.status_code == Unauthorized.code, r.data

        set_logged_user(self.client, users["noright_user"])
        r = self.client.delete(url)
        assert r.status_code == Forbidden.code, r.data

        set_logged_user(self.client, users["self_user"])
        r = self.client.delete(url)
        assert r.status_code == Forbidden.code, r.data

        set_logged_user(self.client, users["user"])
        r = self.client.delete(url)
        assert r.status_code == 204, r.data
        assert sa.inspect(requests["r1"]).was_deleted
        assert sa.inspect(requests["r1"].permission).was_deleted
