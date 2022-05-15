from app.api import bp
from flask import jsonify
from app.modules.firewall.models import Firewall, FirewallPort
from app.modules.rack.models import Rack
from app.modules.network.models import Network
from app.modules.server.models import Server
from app.main.models import Service, Location
from flask import url_for
from app import db
from app.api.errors import bad_request
from flask import request
from app.api.auth import token_auth


@bp.route('/firewall/add', methods=['POST'])
@token_auth.login_required
def create_firewall():
    data = request.get_json() or {}
    for field in ['name', 'status']:
        if field not in data:
            return bad_request('must include %s fields' % field)

    check_firewall = Firewall.query.filter_by(name=data['name']).first()
    if check_firewall is not None:
        return bad_request('Firewall already exist with id: %s' % check_firewall.id)

    firewall = Firewall()
    firewall.from_dict(data)

    db.session.add(firewall)
    db.session.commit()
    #  audit.auditlog_new_post('firewall', original_data=firewall.to_dict(), record_name=firewall.name)

    response = jsonify(firewall.to_dict())

    response.status_code = 201
    response.headers['Location'] = url_for('api.get_firewall', id=firewall.id)
    return response


@bp.route('/firewall/<name>', methods=['GET'])
@token_auth.login_required
def get_firewall_by_name(name):

    check_firewall = Firewall.query.filter_by(name=name).first()
    if check_firewall is None:
        return bad_request('Firewall with name %s dont exist' % name)

    response = jsonify(check_firewall.to_dict())
    response.status_code = 201
    return response


@bp.route('/firewalllist', methods=['GET'])
@token_auth.login_required
def get_firewalllist():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    data = Firewall.to_collection_dict(Firewall.query, page, per_page, 'api.get_firewall')
    return jsonify(data)


@bp.route('/firewall/<int:id>', methods=['GET'])
@token_auth.login_required
def get_firewall(id):
    return jsonify(Firewall.query.get_or_404(id).to_dict())


@bp.route('/firewall/<int:id>', methods=['PUT'])
@token_auth.login_required
def update_firewall(id):
    firewall = Firewall.query.get_or_404(id)
    original_data = firewall.to_dict()

    data = request.get_json() or {}
    firewall.from_dict(data, new_firewall=False)
    db.session.commit()
    #  audit.auditlog_update_post('firewall', original_data=original_data, updated_data=firewall.to_dict(), record_name=firewall.hostname)

    return jsonify(firewall.to_dict())


@bp.route('/firewall/port/add', methods=['POST'])
@token_auth.login_required
def firewall_port_add():
    data = request.get_json() or {}
    for field in ['name', 'firewall']:
        if field not in data:
            return bad_request('must include %s fields' % field)

    firewall = Firewall.query.filter_by(name=data['firewall']).first()
    if firewall is None:
        return bad_request('No such Firewall name exist in the db')
    else:
        print("adding port to firewall: {} {}".format(firewall.name, firewall.id))

    check_sp = FirewallPort.query.filter_by(name=data['name'], firewall_id=firewall.id).first()
    if check_sp is not None:
        return bad_request('FirewallPort already exist with id: %s' % check_sp.id)
    else:
        print("the port {} was not found, adding".format(data['name']))

    network = None
    server = None
    if 'network_id' in data:
        network = Network.query.get(data['network_id'])
    elif 'network_name' in data:
        network = Network.query.filter_by(name=data['network_name']).first()

    if 'server_id' in data:
        server = server.query.get(data['rack_id'])
    elif 'server_name' in data:
        server = Server.query.filter_by(name=data['rack_name'])

    firewall_port = FirewallPort()
    firewall_port.from_dict(data)
    firewall_port.firewall = firewall
    firewall_port.network = network
    firewall_port.server = server

    db.session.add(firewall_port)
    db.session.commit()
    #  audit.auditlog_new_post('firewall', original_data=firewall_port.to_dict(), record_name=firewall_port.name)

    response = jsonify(firewall_port.to_dict())

    response.status_code = 201
    response.headers['Location'] = url_for('api.get_firewall_port', id=firewall_port.id)
    return response


@bp.route('/firewall/port/list', methods=['GET'])
@token_auth.login_required
def get_firewall_port_list():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    data = FirewallPort.to_collection_dict(FirewallPort.query, page, per_page, 'api.get_firewall_port')
    return jsonify(data)


@bp.route('/firewall/port/<int:id>', methods=['GET'])
@token_auth.login_required
def get_firewall_port(id):
    return jsonify(FirewallPort.query.get_or_404(id).to_dict())


@bp.route('/firewall/port/<int:id>', methods=['PUT'])
@token_auth.login_required
def update_firewall_port(id):
    firewall_port = FirewallPort.query.get_or_404(id)
    original_data = firewall_port.to_dict()

    data = request.get_json() or {}
    firewall_port.from_dict(data, new_firewall=False)
    db.session.commit()
    #  audit.auditlog_update_post('firewall', original_data=original_data, updated_data=firewall_port.to_dict(), record_name=firewall_port.name)

    return jsonify(firewall_port.to_dict())
