"""Credential reference, use grant and store ledger (#6757, C-1009).

A reference names one stored secret (by the uuid of the configuration it governs), says where its
material is held and carries the approval it needs before it can be used. A grant allows one
agent binding to use one reference for one subject. The ledger records store writes that are in
flight, so a crash between the store and the database can be settled afterwards.

Nothing here holds secret material or a store path. ``store_locator`` is restricted: it never
goes into a public API, a log line or an audit event. State changes are conditional UPDATEs (see
``utils/credential_state.py``); the ``before_update`` guards at the bottom are a second fence for
anything that flushes through the ORM instead.
"""
import uuid
from datetime import datetime
from typing import Optional

from tools import db_tools, db, config as c
from sqlalchemy import (
    BigInteger, CheckConstraint, DateTime, Index, Integer, SmallInteger, String, UniqueConstraint, event, func, text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import Mapped, mapped_column

OWNERSHIP_CLASSES = ('personal', 'project_shared', 'service', 'scheduled', 'technical')
STORE_KINDS = ('database', 'managed_vault', 'corporate_vault')
REFERENCE_STATES = ('pending', 'validated', 'active', 'suspended', 'retired')
SUBJECT_KINDS = ('user_delegation', 'mandate')
GRANT_STATES = ('pending_approval', 'active', 'suspended', 'revoked')
LEDGER_OPS = ('write', 'delete_all')
LEDGER_STATES = ('intent', 'written', 'committed', 'abandoned')
MATERIAL_STATES = ('pending', 'active', 'retired')
MATERIAL_SOURCES = ('login', 'broker')   # which client redeems an offline grant: auth_oidc's custody source
LEGACY_INDEX = 'uq_credential_reference_live_configuration'
GRANT_LIST_INDEX = 'ix_credential_use_grant_list'
SHARED_INDEX = 'uq_credential_reference_live_shared'
PERSONAL_INDEX = 'uq_credential_reference_live_personal'

# Columns that never change after the row exists (approved_by is set once, see _ONCE)
REFERENCE_IMMUTABLE = frozenset({
    'id', 'project_id', 'configuration_id', 'configuration_uuid', 'provider', 'auth_mode', 'ownership_class',
    'custodian_ref', 'target_ref', 'environment', 'store_kind', 'created_by',
})
GRANT_IMMUTABLE = frozenset({
    'id', 'project_id', 'application_id', 'subject_kind', 'subject_ref', 'agent_binding_ref',
    'toolkit_instance_id', 'credential_ref', 'target_ref', 'created_by',
})
MATERIAL_IMMUTABLE = frozenset({
    'id', 'project_id', 'holder_ref', 'custodian_user_id', 'custodian_subject_ref', 'source', 'store_kind',
    'created_by',
})
_ONCE = frozenset({'approved_by', 'subject_user_id'})


class ImmutableFieldChanged(ValueError):
    """An ORM flush tried to change a column that must stay as it was written."""


def _in_list(column: str, values) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


_ACTIVE_NEEDS_APPROVAL = "approval_ref IS NOT NULL AND policy_revision IS NOT NULL AND approved_by IS NOT NULL"


class CredentialReference(db_tools.AbstractBaseMixin, db.Base):
    __tablename__ = 'credential_reference'
    __table_args__ = (
        UniqueConstraint('project_id', 'id', name='credential_reference_project_id_uc'),
        CheckConstraint(_in_list('ownership_class', OWNERSHIP_CLASSES), name='credential_reference_ownership_ck'),
        CheckConstraint(_in_list('store_kind', STORE_KINDS), name='credential_reference_store_kind_ck'),
        CheckConstraint(_in_list('state', REFERENCE_STATES), name='credential_reference_state_ck'),
        CheckConstraint(
            f"state <> 'active' OR ({_ACTIVE_NEEDS_APPROVAL} "
            "AND generation >= 1 AND validated_generation = generation)",
            name='credential_reference_active_ck'),
        CheckConstraint('approved_by IS NULL OR approved_by <> created_by', name='credential_reference_approver_ck'),
        # One live reference per configuration for every class but personal, and one personal reference per owner of
        # the configuration (#7119). Projects created before the personal class carry the single
        # ``uq_credential_reference_live_configuration`` index until ``create_credential_governance_tables`` swaps it.
        Index(SHARED_INDEX, 'configuration_id', unique=True,
              postgresql_where=text("state <> 'retired' AND ownership_class <> 'personal'")),
        Index(PERSONAL_INDEX, 'configuration_id', text("(custodian_ref->>'subject_ref')"), unique=True,
              postgresql_where=text("state <> 'retired' AND ownership_class = 'personal'")),
        {'schema': c.POSTGRES_TENANT_SCHEMA},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    configuration_id: Mapped[int] = mapped_column(Integer, nullable=False)
    configuration_uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    configuration_generation: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    auth_mode: Mapped[str] = mapped_column(String(32), nullable=False, default='static_secret',
                                           server_default='static_secret')
    ownership_class: Mapped[str] = mapped_column(String(16), nullable=False)
    custodian_ref: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    review_owner: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    verified_principal: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    target_ref: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    environment: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    capabilities: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    store_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    store_locator: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict,
                                                server_default=text("'{}'::jsonb"))
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default='0')
    pending_generation: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    validated_generation: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default='pending', server_default='pending')
    approval_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    policy_revision: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_by: Mapped[int] = mapped_column(Integer, nullable=False)
    approved_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # whoever committed the current generation (an import or a personal value); never the one who approves it
    written_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    state_changed_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    revocation_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default='0')
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class CredentialUseGrant(db_tools.AbstractBaseMixin, db.Base):
    __tablename__ = 'credential_use_grant'
    __table_args__ = (
        UniqueConstraint('agent_binding_ref', 'toolkit_instance_id', 'credential_ref', 'target_ref', 'subject_ref',
                         name='credential_use_grant_uc'),
        CheckConstraint(_in_list('subject_kind', SUBJECT_KINDS), name='credential_use_grant_subject_kind_ck'),
        CheckConstraint(_in_list('state', GRANT_STATES), name='credential_use_grant_state_ck'),
        CheckConstraint(f"state <> 'active' OR ({_ACTIVE_NEEDS_APPROVAL})", name='credential_use_grant_active_ck'),
        CheckConstraint('approved_by IS NULL OR approved_by <> created_by', name='credential_use_grant_approver_ck'),
        Index('ix_credential_use_grant_credential', 'credential_ref', 'state'),
        Index('ix_credential_use_grant_binding', 'agent_binding_ref', 'state'),
        # the operator list (#7294): its filter and default order, so a page and its count read the index
        Index(GRANT_LIST_INDEX, 'project_id', 'target_ref', 'updated_at'),
        {'schema': c.POSTGRES_TENANT_SCHEMA},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    application_id: Mapped[int] = mapped_column(Integer, nullable=False)
    subject_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    # the platform user an ``idp:`` subject was resolved from when the grant was made (null for a mandate, and for a
    # grant made before the column existed until a list resolves it); it names the subject without a member listing
    subject_user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    agent_binding_ref: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    toolkit_instance_id: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_ref: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(256), nullable=False, default='*', server_default='*')
    operations: Mapped[list] = mapped_column(JSONB, nullable=False, default=lambda: ['*'],
                                             server_default=text('\'["*"]\'::jsonb'))
    resource_constraints: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict,
                                                       server_default=text("'{}'::jsonb"))
    obligations: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    approval_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    policy_revision: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_by: Mapped[int] = mapped_column(Integer, nullable=False)
    approved_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    state_changed_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default='1')
    revocation_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default='0')
    state: Mapped[str] = mapped_column(String(16), nullable=False, default='pending_approval',
                                       server_default='pending_approval')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class CredentialStoreLedger(db_tools.AbstractBaseMixin, db.Base):
    __tablename__ = 'credential_store_ledger'
    __table_args__ = (
        UniqueConstraint('credential_ref', 'generation', 'op', name='credential_store_ledger_uc'),
        CheckConstraint(_in_list('op', LEDGER_OPS), name='credential_store_ledger_op_ck'),
        CheckConstraint(_in_list('state', LEDGER_STATES), name='credential_store_ledger_state_ck'),
        CheckConstraint(_in_list('store_kind', STORE_KINDS), name='credential_store_ledger_store_kind_ck'),
        Index('ix_credential_store_ledger_state_updated', 'state', 'updated_at'),
        {'schema': c.POSTGRES_TENANT_SCHEMA},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    credential_ref: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    store_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    op: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default='intent', server_default='intent')
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempts: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1, server_default='1')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class CredentialOfflineMaterial(db_tools.AbstractBaseMixin, db.Base):
    """A person's offline delegated consent (#7131): the refresh token they gave one holder (an autonomous mandate,
    ``mandate:<uuid>``) so its runs can act with their Microsoft sign-in while they are away. The token lives in the
    governed store under this row's id, as ``generation``; the row holds who it belongs to (``custodian_*``, fixed at
    consent), which client redeems it (``source``) and whether it may still be released. Never a value."""
    __tablename__ = 'credential_offline_material'
    __table_args__ = (
        CheckConstraint(_in_list('state', MATERIAL_STATES), name='credential_offline_material_state_ck'),
        CheckConstraint(_in_list('source', MATERIAL_SOURCES), name='credential_offline_material_source_ck'),
        CheckConstraint(_in_list('store_kind', STORE_KINDS), name='credential_offline_material_store_kind_ck'),
        CheckConstraint("state <> 'active' OR generation >= 1", name='credential_offline_material_active_ck'),
        Index('ix_credential_offline_material_holder', 'holder_ref', 'state'),
        {'schema': c.POSTGRES_TENANT_SCHEMA},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    holder_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    custodian_user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    custodian_subject_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    store_kind: Mapped[str] = mapped_column(String(16), nullable=False, default='database', server_default='database')
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default='0')
    state: Mapped[str] = mapped_column(String(16), nullable=False, default='pending', server_default='pending')
    created_by: Mapped[int] = mapped_column(Integer, nullable=False)
    retired_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    retired_reason: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


def _refuse_immutable_change(target, immutable):
    state = inspect(target)
    for name in immutable:
        if state.attrs[name].history.has_changes():
            raise ImmutableFieldChanged(f"{type(target).__name__}.{name} cannot be changed")
    for name in _ONCE:
        if hasattr(target, name) and any(old is not None for old in state.attrs[name].history.deleted):
            raise ImmutableFieldChanged(f"{type(target).__name__}.{name} is set once")


@event.listens_for(CredentialReference, 'before_update')
def _guard_reference(_mapper, _connection, target):
    _refuse_immutable_change(target, REFERENCE_IMMUTABLE)


@event.listens_for(CredentialUseGrant, 'before_update')
def _guard_grant(_mapper, _connection, target):
    _refuse_immutable_change(target, GRANT_IMMUTABLE)


@event.listens_for(CredentialOfflineMaterial, 'before_update')
def _guard_material(_mapper, _connection, target):
    _refuse_immutable_change(target, MATERIAL_IMMUTABLE)
