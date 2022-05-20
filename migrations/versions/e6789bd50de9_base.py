"""base

Revision ID: e6789bd50de9
Revises: 
Create Date: 2022-05-19 20:08:03.497543

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e6789bd50de9'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('certificate',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('userid', sa.String(length=255), nullable=True),
    sa.Column('serial', sa.String(length=255), nullable=True),
    sa.Column('orgunit', sa.String(length=255), nullable=True),
    sa.Column('org', sa.String(length=255), nullable=True),
    sa.Column('country', sa.String(length=255), nullable=True),
    sa.Column('sandns', sa.String(length=4000), nullable=True),
    sa.Column('ca_id', sa.Integer(), nullable=True),
    sa.Column('service_id', sa.Integer(), nullable=True),
    sa.Column('validity_start', sa.DateTime(), nullable=True),
    sa.Column('validity_end', sa.DateTime(), nullable=True),
    sa.Column('cert', sa.String(length=2000), nullable=True),
    sa.Column('status', sa.String(length=140), nullable=True),
    sa.Column('comment', sa.String(length=2000), nullable=True),
    sa.ForeignKeyConstraint(['ca_id'], ['certification_authority.id'], ),
    sa.ForeignKeyConstraint(['service_id'], ['service.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('certification_authority',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=2000), nullable=True),
    sa.Column('certificate_id', sa.Integer(), nullable=True),
    sa.Column('ca_id', sa.Integer(), nullable=True),
    sa.Column('keys_id', sa.Integer(), nullable=True),
    sa.Column('service_id', sa.Integer(), nullable=True),
    sa.Column('approval', sa.Integer(), nullable=True),
    sa.Column('comment', sa.String(length=2000), nullable=True),
    sa.Column('crl_cdp', sa.String(length=2000), nullable=True),
    sa.Column('ocsp_url', sa.String(length=2000), nullable=True),
    sa.ForeignKeyConstraint(['ca_id'], ['certification_authority.id'], ),
    sa.ForeignKeyConstraint(['certificate_id'], ['certificate.id'], ),
    sa.ForeignKeyConstraint(['keys_id'], ['keys.id'], ),
    sa.ForeignKeyConstraint(['service_id'], ['service.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('keys',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('key', sa.String(length=10000), nullable=True),
    sa.Column('password', sa.String(length=100), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=True),
    sa.Column('email', sa.String(length=120), nullable=True),
    sa.Column('password_hash', sa.String(length=128), nullable=True),
    sa.Column('about_me', sa.String(length=140), nullable=True),
    sa.Column('last_seen', sa.DateTime(), nullable=True),
    sa.Column('api_key', sa.String(length=32), nullable=True),
    sa.Column('token', sa.String(length=32), nullable=True),
    sa.Column('token_expiration', sa.DateTime(), nullable=True),
    sa.Column('role', sa.String(length=140), nullable=True),
    sa.Column('active', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_api_key'), ['api_key'], unique=True)
        batch_op.create_index(batch_op.f('ix_user_email'), ['email'], unique=True)
        batch_op.create_index(batch_op.f('ix_user_token'), ['token'], unique=True)
        batch_op.create_index(batch_op.f('ix_user_username'), ['username'], unique=True)

    op.create_table('audit',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('module', sa.String(length=140), nullable=True),
    sa.Column('record_name', sa.String(length=140), nullable=True),
    sa.Column('module_id', sa.Integer(), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('original_data', sa.Text(), nullable=True),
    sa.Column('updated_data', sa.Text(), nullable=True),
    sa.Column('updated_column', sa.String(length=255), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('type', sa.String(length=128), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('crl',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ca_id', sa.Integer(), nullable=True),
    sa.Column('validity_start', sa.DateTime(), nullable=True),
    sa.Column('validity_end', sa.DateTime(), nullable=True),
    sa.Column('pem', sa.String(length=2000), nullable=True),
    sa.ForeignKeyConstraint(['ca_id'], ['certification_authority.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('ocsp',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=140), nullable=True),
    sa.Column('userid', sa.String(length=255), nullable=True),
    sa.Column('serial', sa.String(length=255), nullable=True),
    sa.Column('orgunit', sa.String(length=255), nullable=True),
    sa.Column('org', sa.String(length=255), nullable=True),
    sa.Column('country', sa.String(length=255), nullable=True),
    sa.Column('sandns', sa.String(length=4000), nullable=True),
    sa.Column('ca_id', sa.Integer(), nullable=True),
    sa.Column('keys_id', sa.Integer(), nullable=True),
    sa.Column('cert', sa.String(length=2000), nullable=True),
    sa.Column('validity_start', sa.DateTime(), nullable=True),
    sa.Column('validity_end', sa.DateTime(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('comment', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['ca_id'], ['certification_authority.id'], ),
    sa.ForeignKeyConstraint(['keys_id'], ['keys.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('service',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=140), nullable=True),
    sa.Column('updated', sa.DateTime(), nullable=True),
    sa.Column('color', sa.String(length=140), nullable=True),
    sa.Column('manager_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['manager_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    with op.batch_alter_table('service', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_service_updated'), ['updated'], unique=False)

    op.create_table('service_user',
    sa.Column('service_id', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['service_id'], ['service.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], )
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('service_user')
    with op.batch_alter_table('service', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_service_updated'))

    op.drop_table('service')
    op.drop_table('ocsp')
    op.drop_table('crl')
    op.drop_table('audit')
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_username'))
        batch_op.drop_index(batch_op.f('ix_user_token'))
        batch_op.drop_index(batch_op.f('ix_user_email'))
        batch_op.drop_index(batch_op.f('ix_user_api_key'))

    op.drop_table('user')
    op.drop_table('keys')
    op.drop_table('certification_authority')
    op.drop_table('certificate')
    # ### end Alembic commands ###
