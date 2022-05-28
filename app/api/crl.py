from app.api import bp
from flask import jsonify
from app.modules.crl.models import Crl
from flask import url_for
from app import db
from app.api.errors import bad_request
from flask import request
from app.api.auth import token_auth
from app.modules.ca.models import CertificationAuthority
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization


@bp.route('/crl', methods=['POST'])
@token_auth.login_required
def create_crl():
    data = request.get_json() or {}

    ca = None
    if 'ca_name' in data:
        ca = CertificationAuthority.query.filter_by(name=data['ca_name']).first()
    elif 'ca_id' in data:
        ca = CertificationAuthority.query.get(data['ca_id'])

    if ca is None:
        return bad_request('must include ca_name or ca_id in fields')

    validity_start = datetime.now()
    if 'validity_start' in data:
        validity_start = data['validity_start']

    validity_end = datetime.now() + timedelta(hours=24)
    if 'validity_end' in data:
        validity_end = data['validity_end']

    crl = Crl(validity_start=validity_start,
              validity_end=validity_end)

    crl_obj = ca.create_crl(crl, b"foo123")

    pemcrl = crl_obj.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    crl.pem = pemcrl
    crl.ca = ca

    db.session.add(crl)
    db.session.commit()
     #  audit.auditlog_new_post('crl', original_data=crl.to_dict(), record_name=crl.name)

    response = jsonify(crl.to_dict())

    response.status_code = 201
    response.headers['Crl'] = url_for('api.get_crl', id=crl.id)
    return response


@bp.route('/crl/<ca_name>', methods=['GET'])
@token_auth.login_required
def get_crl_by_name(ca_name):

    ca = None
    if ca_name is not None:
        ca = CertificationAuthority.query.filter_by(name=ca_name).first()

    if ca is None:
        return bad_request('must include ca_name or ca_id in fields')

    crl = Crl.query.filter_by(ca_id=ca.id).first()
    if crl is None:
        return bad_request('Crl dont exist name: %s' % ca_name)

    response = jsonify(crl.to_dict())
    response.status_code = 201

    return response


@bp.route('/crl/list', methods=['GET'])
@token_auth.login_required
def get_crllist():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    data = Crl.to_collection_dict(Crl.query.order_by(Crl.validity_end), page, per_page, 'api.get_cert_list')
    return jsonify(data)


@bp.route('/crl/<int:id>', methods=['GET'])
@token_auth.login_required
def get_crl(id):
    return jsonify(Crl.query.get_or_404(id).to_dict())
