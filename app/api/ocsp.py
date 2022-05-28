from app.api import bp
from flask import jsonify
from app.modules.ocsp.models import Ocsp
from app.main.models import User
from flask import url_for
from app import db
from app.api.errors import bad_request
from flask import request
from app.api.auth import token_auth
from app.modules.ca.models import CertificationAuthority
from app.modules.certificate.models import Certificate
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from app.main.models import Service
from datetime import datetime
from app.modules.keys.models import Keys
from cryptography.hazmat.primitives import serialization


@bp.route('/ocsp/add', methods=['POST'])
@token_auth.login_required
def ocsp_add():
    data = request.get_json() or {}
    for field in ['status', 'validity_start', 'validity_end']:
        if field not in data:
            return bad_request('must include field: %s' % field)

    check_ocsp = Ocsp.query.filter_by(name=data['name']).first()
    if check_ocsp is not None:
        return bad_request(f'OCSP responder with name {data["name"]} already exist with id: {check_ocsp.id}')

    # use ca to generate cert
    ocsp_responder = Ocsp(status=data['status'],
                          validity_start=datetime.strptime(data['validity_start'], "%Y-%m-%d"),
                          validity_end=datetime.strptime(data['validity_end'], "%Y-%m-%d")
                          )
    certname_set = False
    if 'name' in data:
        ocsp_responder.name = data['name']
        certname_set = True
    if 'serial' in data:
        ocsp_responder.serial = data['serial']
        certname_set = True
    if 'orgunit' in data:
        ocsp_responder.orgunit = data['orgunit']
        certname_set = True
    if 'org' in data:
        ocsp_responder.org = data['org']
        certname_set = True
    if 'country' in data:
        ocsp_responder.country = data['country']
        certname_set = True

    ocsp_responder.profile = "ocsp"

    # todo inline check, see auth username ...
    if certname_set is False:
        return bad_request('must include some name fields')

    service = None
    if 'service_name' in data:
        service = Service.query.filter_by(name=data['service_name']).first()
    elif 'service_id' in data:
        service = Service.query.get(data['service_id'])

    if service is None:
        return bad_request('must include service_name or service_id in fields')
    else:
        ocsp_responder.service = service

    ca = None
    if 'ca' in data:
        ca = CertificationAuthority.query.filter_by(name=data['ca']).first()
    if ca is None:
        ca = CertificationAuthority.query.get(data['ca'])
    if ca is None:
        return bad_request('must include ca_name or ca_id in fields')
    else:
        ocsp_responder.ca = ca

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    keys = Keys(key=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"foo123")),
            password=b"foo123")
    signed = ca.create_cert(ocsp_responder, b"foo123", b"foo123", keys)

    pemcert = signed.public_bytes(serialization.Encoding.PEM).decode()

#        db.session.add(keys)
    ocsp_responder.keys = keys
    ocsp_responder.cert = pemcert

    db.session.add(keys)
    db.session.add(ocsp_responder)
    db.session.commit()

    response = jsonify(ocsp_responder.to_dict())

    response.status_code = 201
    response.headers['Ocsp'] = url_for('api.get_ocsp_by_id', id=ocsp_responder.id)
    return response


@bp.route('/ocsp/<name>', methods=['GET'])
@token_auth.login_required
def get_ocsp_by_name(name):

    ocsp_responder = Ocsp.query.filter_by(name=name).first()
    if ocsp_responder is None:
        return bad_request('OCSP responder with name %s dont exist' % name)

    response = jsonify(ocsp_responder.to_dict())

    response.status_code = 201
    return response


@bp.route('/ocsp/<int:id>', methods=['GET'])
@token_auth.login_required
def get_ocsp_by_id(id):
    return jsonify(Ocsp.query.get_or_404(id).to_dict())


@bp.route('/ocsp/list', methods=['GET'])
@token_auth.login_required
def get_ocsp_list():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    data = Ocsp.to_collection_dict(Ocsp.query, page, per_page, 'api.get_ocsp_list')
    return jsonify(data)

#
# @bp.route('/safe/<int:id>', methods=['PUT'])
# @token_auth.login_required
# def update_safe(id):
#     safe = Safe.query.get_or_404(id)
#     original_data = safe.to_dict()
# # TODO: disable "old" OCSP:s
#     data = request.get_json() or {}
#     safe.from_dict(data, new_safe=False)
#     db.session.commit()
#      #  audit.auditlog_update_post('safe', original_data=original_data, updated_data=safe.to_dict(), record_name=safe.name)
#
#     return jsonify(safe.to_dict())
