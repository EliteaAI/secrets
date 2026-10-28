"""C-1009 #6756 step 4: the ``entra_delegated`` credential reference is a container only.

It stores no secret, no refresh token and no token: a descriptor of how a token is obtained at release, on behalf of the
person who runs the agent. The real services and handlers run over SQLite (``fixtures/governance.py``); the store, audit
trail, configurations, identity service and elitea_core's probe are fakes. Every value here is made up for the tests.
"""
import uuid

import pytest

from unit.test_7119_personal_references import APPROVER, CREATOR, OWNER, PROJECT, World

TENANT = "11111111-2222-3333-4444-555555555555"
GRAPH = "https://graph.microsoft.com"


def descriptor(**over):
    found = {"oauth_app_id": "platform", "tenant_id": TENANT, "resource": GRAPH,
             "scopes": [f"{GRAPH}/Sites.Selected"], "assertion_source": "login"}
    found.update(over)
    return found


class Delegated(World):
    def __init__(self, gov, monkeypatch):
        super().__init__(gov, monkeypatch)
        self.probes, self.probe_answer, self.app_answer, self.app_asks = [], None, True, []

        def entra_delegated_probe(project_id, reference_id, delegation, person):
            self.probes.append((project_id, reference_id, dict(delegation), dict(person)))
            return self.probe_answer

        def entra_delegated_app_available(project_id, delegation):
            self.app_asks.append((project_id, dict(delegation)))
            return self.app_answer

        monkeypatch.setattr(gov.core, "entra_delegated_probe", entra_delegated_probe, raising=False)
        monkeypatch.setattr(gov.core, "entra_delegated_app_available", entra_delegated_app_available, raising=False)

    def sharepoint(self, secrets=None):
        return self.gov.configurations.add(PROJECT, type_="sharepoint", secrets=secrets or {})

    def create_delegated(self, owner=OWNER, config=None, ownership_class="personal", **body):
        body.setdefault("auth_mode", "entra_delegated")
        body.setdefault("delegation", descriptor())
        return self.create(owner, config=config or self.sharepoint(), ownership_class=ownership_class, store_kind=None,
                           **body)

    def create(self, owner=OWNER, config=None, project=PROJECT, actor=None, ownership_class="personal",
               store_kind="database", **extra):
        config = config or self.gov.configurations.add(project)
        body = {"configuration_uuid": config.uuid, "ownership_class": ownership_class, **extra}
        if store_kind is not None:
            body["store_kind"] = store_kind
        if owner is not None:
            body["owner_user_id"] = owner
        reply = self.call("credential_references", "post", project, body=body, actor=actor)
        self.config = config
        return reply


@pytest.fixture
def w(gov, monkeypatch):
    world = Delegated(gov, monkeypatch)
    gov.stores.get_store_calls.clear()
    return world


def store_untouched(gov):
    return gov.stores.get_store_calls == [] and all(not store.__dict__.get("data") for store in gov.stores.stores.values())


def test_a_delegated_reference_is_created_with_its_descriptor_and_nothing_in_any_store(w):
    body, status = w.create_delegated(delegation=descriptor(tenant_id=TENANT.upper(), scopes=[
        f"{GRAPH}/Sites.Selected", f"{GRAPH}/Sites.Selected"]))
    assert status == 201, body
    row = w.row(body["id"])
    assert (row.auth_mode, row.generation, row.state, row.store_kind, row.pending_generation) == (
        "entra_delegated", 1, "pending", "database", None)
    assert row.capabilities == {"delegation": descriptor()}          # canonical: tenant lower-case, scopes once
    assert row.configuration_generation == w.config.generation
    assert store_untouched(w.gov)
    assert w.reasons() == ["CREDENTIAL_REF_PENDING"]


def test_the_reference_row_shows_the_kind_and_the_descriptor(w):
    ref = w.create_delegated()[0]["id"]
    detail, status = w.call("credential_reference", "get", PROJECT, uuid.UUID(ref))
    assert status == 200 and (detail["auth_mode"], detail["delegation"]) == ("entra_delegated", descriptor())


def test_a_configuration_holding_a_secret_cannot_become_a_delegated_container(w):
    body, status = w.create_delegated(config=w.sharepoint({"client_secret": "a-secret-value-made-up"}))
    assert (status, body["code"]) == (409, "DELEGATED_SECRET_PRESENT")
    assert store_untouched(w.gov) and w.reasons() == []


@pytest.mark.parametrize("delegation", [
    descriptor(refresh_token="a-refresh-token-made-up"),                  # an extra, secret-shaped field
    descriptor(client_secret="x"),                                       # a custom app: not offered (admin app only)
    descriptor(scopes=[".".join(["header", "claims", "signature"])]),      # a token where a scope goes
    descriptor(resource="https://evil.example"),
    descriptor(tenant_id="common"),
    descriptor(oauth_app_id="not-an-app"),
    descriptor(assertion_source="password"),
    descriptor(scopes=[]),
    descriptor(scopes=[f"{GRAPH}/.default", f"{GRAPH}/Sites.Selected"]),   # Entra refuses .default with named scopes
    {key: value for key, value in descriptor().items() if key != "scopes"},
    "not-a-dict",
])
def test_a_descriptor_with_anything_but_its_own_fields_is_refused(w, delegation):
    body, status = w.create_delegated(delegation=delegation)
    assert status == 400 and body["code"] in ("INVALID_DESCRIPTOR", "INVALID_REQUEST"), body
    assert w.reasons() == []


@pytest.mark.parametrize("body", [
    {"auth_mode": "entra_delegated", "delegation": descriptor(), "store_kind": "database"},
    {"delegation": descriptor(), "store_kind": "database"},
    {"auth_mode": "static_secret", "delegation": descriptor()},
    {"auth_mode": "entra_delegated"},
])
def test_the_kind_store_and_descriptor_go_together(w, body):
    config = w.sharepoint()
    reply, status = w.call("credential_references", "post", PROJECT, body={
        "configuration_uuid": config.uuid, "ownership_class": "personal", "owner_user_id": OWNER, **body})
    assert status == 400, reply


def test_only_sharepoint_can_be_delegated(w):
    body, status = w.create_delegated(config=w.gov.configurations.add(PROJECT, type_="github", secrets={}))
    assert (status, body["code"]) == (400, "UNSUPPORTED_PROVIDER")


def test_a_delegated_reference_takes_no_value_and_no_import(w):
    ref = w.create_delegated()[0]["id"]
    body, status = w.put(ref, fields={"access_token": "a-token-made-up"}, expected_generation=1)
    assert (status, body["code"]) == (409, "DELEGATED_NO_VALUE")
    shared = w.create_delegated(owner=None, ownership_class="project_shared")[0]["id"]
    result = w.onboarding.manage_reference(f"project_id={PROJECT};action=import;ref={shared}", CREATOR)
    assert result["code"] == "DELEGATED_NO_VALUE"
    assert store_untouched(w.gov)


def test_the_probe_asks_elitea_core_for_the_custodian_and_validates_the_reference(w):
    ref = w.create_delegated()[0]["id"]
    reply, status = w.action(ref, "probe", actor=OWNER)
    assert status == 200 and reply["state"] == "validated", reply
    [(project_id, reference_id, delegation, person)] = w.probes
    assert (project_id, reference_id, person) == (PROJECT, ref, {"issuer": None, "tid": "t1", "oid": "o30"})
    assert delegation == {**descriptor(), "ownership_class": "personal", "custodian_subject_ref": "idp:t1:o30"}
    assert w.row(ref).validated_generation == 1 and store_untouched(w.gov)
    assert w.reasons()[-1] == "CREDENTIAL_REF_VALIDATED"


def test_a_failed_probe_names_the_exchange_reason_and_leaves_the_reference_pending(w):
    ref = w.create_delegated()[0]["id"]
    w.probe_answer = "DENIED_ASSERTION_UNAVAILABLE"
    reply, status = w.action(ref, "probe", actor=OWNER)
    assert (status, reply["code"], reply["reason"]) == (409, "DELEGATION_PROBE_FAILED", "DENIED_ASSERTION_UNAVAILABLE")
    assert w.row(ref).state == "pending"
    event = w.events()[-1]
    assert (event["event_type"], event["reason_code"], event["outcome"]) == ("probe", "DENIED_ASSERTION_UNAVAILABLE", "failed")


def test_a_project_delegated_reference_is_probed_for_the_operator(w):
    ref = w.create_delegated(owner=None, ownership_class="project_shared")[0]["id"]
    assert w.action(ref, "probe", actor=APPROVER)[1] == 200
    assert w.probes[0][3] == {"issuer": None, "tid": "t1", "oid": "o20"}


def active_delegated(w):
    ref = w.create_delegated()[0]["id"]
    assert w.action(ref, "probe", actor=OWNER)[1] == 200
    assert w.action(ref, "approve", actor=APPROVER, approval_ref="CHG-1", policy_revision="rev-1")[1] == 200
    assert w.action(ref, "activate", actor=APPROVER)[1] == 200
    return ref


def test_the_release_answers_the_descriptor_and_never_reads_or_writes_a_store(w):
    """Roman, 2026-10-28 (binding): nothing is stored for a delegated credential, before or after a release."""
    ref = active_delegated(w)
    release = w.gov.module("utils.credential_release")
    answer = release.release_materials(PROJECT, [{"ref_id": ref, "generation": 1}], str(uuid.uuid4()), "worker:1")
    assert answer["ok"] is True
    value = answer["values"][ref]
    assert value.generation == 1 and value.delegation == {
        **descriptor(), "ownership_class": "personal", "custodian_subject_ref": "idp:t1:o30"}
    assert not hasattr(value, "fields") and "token" not in repr(value).lower()
    assert store_untouched(w.gov)


def test_the_facts_name_the_kind(w):
    ref = active_delegated(w)
    facts = w.gov.module("methods.credential_facts").Method.credential_use_facts(
        object(), PROJECT, [w.row(ref).configuration_id], [], personal_subject_ref="idp:t1:o30")
    [found] = facts["references"].values()
    assert found["auth_mode"] == "entra_delegated" and found["state"] == "active"


def test_retiring_a_delegated_reference_deletes_nothing_because_nothing_was_stored(w):
    ref = active_delegated(w)
    w.gov.stores.get_store_calls.clear()
    reply, status = w.action(ref, "retire")
    assert status == 200 and "material_deleted" not in reply and w.gov.stores.get_store_calls == []


def test_an_operator_cannot_try_someone_elses_microsoft_sign_in(w):
    ref = w.create_delegated()[0]["id"]
    reply, status = w.action(ref, "probe", actor=APPROVER)
    assert (status, reply["code"]) == (403, "DELEGATED_OWNER_PROBE")
    assert w.probes == [] and w.row(ref).state == "pending"


def test_a_descriptor_whose_app_does_not_resolve_is_not_stored(w):
    w.app_answer = False
    body, status = w.create_delegated(delegation=descriptor(oauth_app_id=str(uuid.uuid4())))
    assert (status, body["code"]) == (409, "OAUTH_APP_UNAVAILABLE") and w.reasons() == []
    assert w.app_asks[0][0] == PROJECT
