"""Add role column to user

Revision ID: bfadc10b2a07
Revises: 
Create Date: 2025-12-04 20:19:59.948997

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bfadc10b2a07'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # drop obsolete table if it exists
    if 'stroke_record' in inspector.get_table_names():
        op.drop_table('stroke_record')

    # collect existing cols if table exists
    existing_cols = [c['name'] for c in inspector.get_columns('user')] if 'user' in inspector.get_table_names() else []
    role_added = False

    # add role column safely (nullable + server_default) if missing
    if 'user' in inspector.get_table_names() and 'role' not in existing_cols:
        op.add_column('user', sa.Column('role', sa.String(length=20), nullable=True, server_default=sa.text("'patient'")))
        role_added = True

    # ensure any NULL role values get a value
    if 'user' in inspector.get_table_names():
        op.execute("UPDATE user SET role='patient' WHERE role IS NULL")

    # perform the table-recreate alterations in a single batch (works on SQLite)
    if 'user' in inspector.get_table_names():
        with op.batch_alter_table('user', schema=None) as batch_op:
            batch_op.alter_column(
                'username',
                existing_type=sa.VARCHAR(length=150),
                type_=sa.String(length=64),
                existing_nullable=False
            )
            batch_op.alter_column(
                'password_hash',
                existing_type=sa.VARCHAR(length=200),
                type_=sa.String(length=128),
                existing_nullable=False
            )
            # set role non-nullable via batch (only if it exists or was just added)
            if 'role' in existing_cols or role_added:
                batch_op.alter_column(
                    'role',
                    existing_type=sa.String(length=20),
                    existing_nullable=True,
                    nullable=False,
                    server_default=None
                )

def downgrade():
    # keep downgrade simple and safe
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if 'user' in inspector.get_table_names():
        with op.batch_alter_table('user', schema=None) as batch_op:
            # revert column types if desired (optional)
            pass
    if 'user' in inspector.get_table_names():
        op.drop_column('user', 'role')
    # recreate stroke_record if needed (optional)
