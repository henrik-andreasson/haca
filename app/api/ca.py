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


@bp.route('/ca/generate', methods=['POST'])
@token_auth.login_required
def create_ca():
    data = request.get_json() or {}
    for field in ['name', 'validity_start', 'validity_end']:
        if field not in data:
            return bad_request('must include %s fields' % field)

    print(f'incoming ca: {data["ca"]}')
    if data['ca'] == "-1":
        # -1 == self signed
        ca_id = -1
    else:
        ca = CertificationAuthority.query.get(data['ca'])
        if ca is None:
            return bad_request('ca must be a valid ca id or -1 for self-signed')
        else:
            ca_id = ca.id

    cert = Certificate(name=data['name'],
                       validity_start=datetime.strptime(data['validity_start'], "%Y-%m-%d"),
                       validity_end=datetime.strptime(data['validity_end'], "%Y-%m-%d"),
                       status="active"
                       )
    ca = CertificationAuthority(name=data['name'],
                                ca_id=ca_id,
                                crl_cdp=data['crl_cdp'],
                                ocsp_url=data['ocsp_url']
                            )

    service = None
    if 'service_name' in data:
        service = Service.query.filter_by(name=data['service_name']).first()
    elif 'service_id' in data:
        service = Service.query.get(data['service_id'])

    if service is None:
        return bad_request('must include service_name or service_id in fields')

    ca.service = service
    cert.service = service
    ca.create_ca(cert, passphrase=b"foo123")
    db.session.add(ca)
    db.session.commit()

    response = jsonify(ca.to_dict())

    response.status_code = 201
    return response


@bp.route('/ca/<name>', methods=['GET'])
@token_auth.login_required
def get_ca_by_name(name):

    ca = CertificationAuthority.query.filter_by(name=name).first()
    if ca is None:
        return bad_request('Certificate with name %s dont exist' % name)

    response = jsonify(ca.to_dict())
    response.status_code = 201
    return response


@bp.route('/ca/list', methods=['GET'])
@token_auth.login_required
def get_ca_list():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    data = CertificationAuthority.to_collection_dict(CertificationAuthority.query, page, per_page, 'api.get_ca_list')
    return jsonify(data)


@bp.route('/ca/<int:id>', methods=['GET'])
@token_auth.login_required
def get_ca(id):
    return jsonify(CertificationAuthority.query.get_or_404(id).to_dict())
