"""C-1009 (#6946): the release path against the local dev Vault (centry c1009-dev overlay). Skipped unless
C1009_VAULT_ADDR is set; needs the real port types (C1009_REAL_PORT_DIR) and ``hvac``.

Environment:
  C1009_VAULT_ADDR      e.g. http://vault.localhost:8200 (http only for localhost / *.localhost / 127.0.0.1)
  C1009_VAULT_JWT_PATH  file holding a JWT whose subject is bound to role elitea-main
  C1009_VAULT_TENANT    tenant segment (default: local)
  C1009_REAL_PORT_DIR   the ``tools/secret_stores`` directory of the shared checkout
"""
import os
import sys
import uuid
from importlib import import_module
from types import SimpleNamespace

import pytest

PROJECT = 3
pytestmark = [
    pytest.mark.vault_dev,
    pytest.mark.skipif(not (os.environ.get("C1009_VAULT_ADDR") and os.environ.get("C1009_REAL_PORT_DIR")),
                       reason="C1009_VAULT_ADDR and C1009_REAL_PORT_DIR not set"),
]


@pytest.fixture(name="vault")
def _vault(gov):
    pytest.importorskip("hvac")
    port = sys.modules["secret_stores_real"]
    cfg = SimpleNamespace(
        CORPORATE_VAULT_ADDR=os.environ["C1009_VAULT_ADDR"],
        CORPORATE_VAULT_TENANT_SEGMENT=os.environ.get("C1009_VAULT_TENANT", "local"),
        CORPORATE_VAULT_AUTH_METHOD="jwt", CORPORATE_VAULT_JWT_PATH=os.environ["C1009_VAULT_JWT_PATH"],
        CORPORATE_VAULT_INSECURE_DEV_HTTP=os.environ["C1009_VAULT_ADDR"].startswith("http://"))
    store = import_module(f"{port.__name__}.corporate_vault").CorporateVaultSecretStore(cfg)
    gov.stores.get_store = lambda store_kind, *, governed: store
    return port, store


def test_release_reads_the_requested_generation_from_vault(gov, vault):
    port, store = vault
    ref_id = uuid.uuid4()
    sref = port.StoreRef(ref_id, PROJECT, "corporate_vault", {})
    mint = port.CredentialStoreProvider.mint
    for generation, value in ((1, "live-fixture-one"), (2, "live-fixture-two")):
        store.write(sref, port.SecretValue({"api_key": value}, generation), expected_version=generation - 1,
                    ctx=mint("onboard", decision_id=str(uuid.uuid4()), actor_ref="test", project_id=PROJECT,
                             ref_id=ref_id))
    try:
        release = gov.module("utils.credential_release").release_material
        gov.add_reference(PROJECT, state="active", generation=1, store_kind="corporate_vault", id=ref_id)
        answer = release(PROJECT, ref_id, 1, str(uuid.uuid4()), "test")  # Vault holds version 2 as well
        assert answer["ok"] and answer["value"].fields["api_key"].get_secret_value() == "live-fixture-one"
        gov.db.execute(PROJECT, "UPDATE tenant.credential_reference SET generation = 2, validated_generation = 2 "
                                "WHERE id = :id", id=ref_id.hex)
        answer = release(PROJECT, ref_id, 2, str(uuid.uuid4()), "test")
        assert answer["ok"] and answer["value"].fields["api_key"].get_secret_value() == "live-fixture-two"
        assert release(PROJECT, ref_id, 1, str(uuid.uuid4()), "test")["reason_code"] == "CREDENTIAL_GENERATION_MISMATCH"
    finally:
        store.delete_all(sref, mint("retire", decision_id=str(uuid.uuid4()), actor_ref="test", project_id=PROJECT,
                                    ref_id=ref_id))
