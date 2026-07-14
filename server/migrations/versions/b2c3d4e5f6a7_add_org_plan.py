"""add organization plan (individual/team/enterprise)

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-07-14 03:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DEFAULT_ORG_ID = '00000000000000000000000000000001'


def upgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('plan', sa.String(length=16),
                                      nullable=False, server_default='individual'))
    # The pre-existing default organization keeps full (enterprise) features so
    # nothing that worked before becomes gated.
    op.execute(f"UPDATE organizations SET plan='enterprise' WHERE id='{DEFAULT_ORG_ID}'")


def downgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('plan')
