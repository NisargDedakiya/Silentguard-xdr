"""add organization purchase keys (admin_key_hash, invite_key)

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-07-17 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('admin_key_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('invite_key', sa.String(length=48), nullable=True))
        batch_op.create_index(batch_op.f('ix_organizations_admin_key_hash'),
                              ['admin_key_hash'], unique=False)
        batch_op.create_index(batch_op.f('ix_organizations_invite_key'),
                              ['invite_key'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_organizations_invite_key'))
        batch_op.drop_index(batch_op.f('ix_organizations_admin_key_hash'))
        batch_op.drop_column('invite_key')
        batch_op.drop_column('admin_key_hash')
