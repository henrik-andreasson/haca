from app.api import bp
from flask import jsonify
from app.modules.certificate.models import Certificate
from app.main.models import Service
from flask import url_for
from app import db
from app.api.errors import bad_request
from flask import request
from app.api.auth import token_auth
from app.modules.keys.models import Keys
from app.modules.ca.models import CertificationAuthority
from cryptography.hazmat.primitives import serialization
from datetime import datetime


@bp.route('/cert/generate', methods=['POST'])
@token_auth.login_required
def create_cert():
    data = request.get_json() or {}
    for field in ['name', 'status', 'validity_start', 'validity_end']:
        if field not in data:
            return bad_request('must include %s fields' % field)

    cert = Certificate(status=data['status'],
                       validity_start=datetime.strptime(data['validity_start'], "%Y-%m-%d"),
                       validity_end=datetime.strptime(data['validity_end'], "%Y-%m-%d")
                       )
    certname_set = False
    if 'name' in data:
        cert.name = data['name']
        certname_set = True
    if 'userid' in data:
        cert.userid = data['userid']
        certname_set = True
    if 'serial' in data:
        cert.serial = data['serial']
        certname_set = True
    if 'orgunit' in data:
        cert.orgunit = data['orgunit']
        certname_set = True
    if 'org' in data:
        cert.org = data['org']
        certname_set = True
    if 'country' in data:
        cert.country = data['country']
        certname_set = True
    if 'profile' in data:
        cert.profile = "server"
    else:
        cert.profile = data['profile']

    if 'sandns' in data:
        cert.sandns = data['sandns']

    if certname_set is False:
        return bad_request('must include some name fields')

    service = None
    if 'service_name' in data:
        service = Service.query.filter_by(name=data['service_name']).first()
    elif 'service_id' in data:
        service = Service.query.get(data['service_id'])

    if service is None:
        return bad_request('must include service_name or service_id in fields')

    cert.service = service

    ca = None
    if 'ca' in data:
        ca = CertificationAuthority.query.filter_by(name=data['ca']).first()
    else:
        ca = CertificationAuthority.query.get(data['ca'])

    if ca is None:
        return bad_request('must include ca with the name or id in fields')

    cert.ca = ca
    keys = Keys()
    signed = ca.create_cert(cert, b"foo123", b"foo123", keys)
    pemcert = signed.public_bytes(serialization.Encoding.PEM).decode()
    pemcacert = cert.ca.certificate.cert

    cert.certserialnumber = str(signed.serial_number)
    cert.cert = pemcert
    db.session.add(cert)
    db.session.commit()
    # audit.auditlog_new_post('cert', original_data=cert.to_dict(), record_name=cert.name)
    response_info = cert.parse_cert()
    response_info['pemkey'] = keys.keys.decode()
    response_info['pemcert'] = pemcert
    response_info['pemcacert'] = pemcacert

    response = jsonify(response_info)

    response.status_code = 201
    return response


@bp.route('/cert/<name>', methods=['GET'])
@token_auth.login_required
def get_cert_by_name(name):

    cert = Certificate.query.filter_by(name=name).first()
    if cert is None:
        return bad_request('Certificate with name %s dont exist' % name)

    response = jsonify(cert.to_dict())
    response.status_code = 201
    return response


@bp.route('/cert/list', methods=['GET'])
@token_auth.login_required
def get_cert_list():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    data = Certificate.to_collection_dict(Certificate.query, page, per_page, 'api.get_cert_list')
    return jsonify(data)


@bp.route('/cert/<int:id>', methods=['GET'])
@token_auth.login_required
def get_cert(id):
    return jsonify(Certificate.query.get_or_404(id).to_dict())


@bp.route('/cert/<int:id>', methods=['PUT'])
@token_auth.login_required
def update_cert(id):
    cert = Certificate.query.get_or_404(id)
    original_data = cert.to_dict()

    data = request.get_json() or {}
    cert.from_dict(data, new_firewall=False)
    db.session.commit()
    #  audit.auditlog_update_post('firewall', original_data=original_data, updated_data=firewall.to_dict(), record_name=firewall.hostname)

    return jsonify(cert.to_dict())
