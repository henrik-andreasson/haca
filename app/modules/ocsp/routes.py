from flask import render_template, flash, redirect, url_for, request, \
  current_app, make_response, jsonify
from flask_login import login_required
from app import db
from app.main import bp
from app.modules.ocsp.models import Ocsp
from app.modules.ocsp.forms import OcspForm, FilterOcspListForm
from flask_babel import _
from sqlalchemy import desc, asc
from app.modules.ca.models import CertificationAuthority
from app.modules.keys.models import Keys
from app.modules.certificate.models import Certificate
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from datetime import datetime, timedelta
from cryptography.x509 import ReasonFlags
from json import dumps


@bp.route('/ocsp/add', methods=['GET', 'POST'])
@login_required
def ocsp_add():
    if 'cancel' in request.form:
        return redirect(request.referrer)

    form = OcspForm(formdata=request.form)

    if request.method == 'POST' and form.validate_on_submit():

        ca = CertificationAuthority.query.get(form.ca.data)
        if ca is None:
            flash('CA is required')
            return redirect(request.referrer)

        # use ca to generate cert
        ocsp_responder = Ocsp(status=form.status.data,
                    validity_start=form.validity_start.data,
                    validity_end=form.validity_end.data,
                    comment=form.comment.data,
                    )
        ocsp_responder.ca = ca
        certname_set = False
        if form.name.data is not None:
            ocsp_responder.name = form.name.data
            certname_set = True
        if form.serial.data is not None:
            ocsp_responder.serial = form.serial.data
            certname_set = True
        if form.orgunit.data is not None:
            ocsp_responder.orgunit = form.orgunit.data
            certname_set = True
        if form.org.data is not None:
            ocsp_responder.org = form.org.data
            certname_set = True
        if form.country.data is not None:
            ocsp_responder.country = form.country.data
            certname_set = True

        ocsp_responder.profile = "ocsp"

        # todo inline check, see auth username ...
        if certname_set is False:
            flash('At least one name field is required')
            return redirect(request.referrer)

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

        flash(_(f'The new cert is now created {ocsp_responder.name}!'))

        return render_template('ocsp.html', title=_('OCSP Certificate created'),
                               cert=ocsp_responder, htmlcert=pemcert
                               )
    else:
        return render_template('ocsp.html', title=_('Add OCSP Certificate'),
                               form=form)


@bp.route('/ocsp/list/', methods=['GET', 'POST'])
@login_required
def ocsp_list():

    page = request.args.get('page', 1, type=int)

    form = FilterOcspListForm()

    ocsps1 = Ocsp.query.order_by(Ocsp.id).all()
    ocsps = Ocsp.query.order_by(Ocsp.id).paginate(
            page, current_app.config['POSTS_PER_PAGE'], False)
    for o in ocsps1:
        print(f'debug ocsp:{o.name}')

    if request.method == 'POST' and form.validate_on_submit():

        if form.ca.data is not None:
            ca = CertificationAuthority.query.get(form.ca.data)
            if ca is not None:
                ocsps = Ocsp.query.filter_by(ca_id=ca.id).paginate(
                    page, current_app.config['POSTS_PER_PAGE'], False)

    next_url = url_for('main.cert_list', page=ocsps.next_num) \
        if ocsps.has_next else None
    prev_url = url_for('main.certs_list', page=ocsps.prev_num) \
        if ocsps.has_prev else None

    return render_template('ocsp.html', title=_('OCSP'),
                           ocsps=ocsps.items, next_url=next_url,
                           prev_url=prev_url, form=form)


@bp.route('/ocsp/info/<int:id>', methods=['GET', 'POST'])
@login_required
def ocsp_info(id):

    if id is None:
        flash(_('OCSP id missing!'))
        return redirect(request.referrer)

    ocsp = Ocsp.query.get(id)
    if ocsp is None:
        flash(_('OCSP id is missing!'))
        return redirect(request.referrer)

    return render_template('ocsp.html', title=_('OCSP'),
                           ocsp=ocsp)


@bp.route('/ocsp/query/', methods=['GET', 'POST'])
def ocsp_query():
    start_query = datetime.now()
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import load_pem_x509_certificate

    length = int(request.headers['content-length'])
    if length > 10000:
        print(f'to much data {length}')
        return None

    data = request.get_data(cache=False, as_text=False, parse_form_data=False)
    # import pprint
    # pp = pprint.PrettyPrinter()
    # pp.pprint(data)
    ocsp_req = ocsp.load_der_ocsp_request(data)
#     print(f'''
# ocsp req serial:  {ocsp_req.serial_number}
# issuer_key hash:  {ocsp_req.issuer_key_hash}
# issuer_name_hash: {ocsp_req.issuer_name_hash}
# hash_algorithm:   {ocsp_req.hash_algorithm}
# ''')
#     for e in ocsp_req.extensions:
#         print(f'extensions:       {e}')

    matched_ca = None
    issuer = None
    for ca in CertificationAuthority.query.order_by(CertificationAuthority.id).all():
        curr_issuer = load_pem_x509_certificate(ca.certificate.cert.encode('utf-8'))
        ca_issuer_key_hash = hashes.Hash(ocsp_req.hash_algorithm)
        ca_issuer_key_hash.update(ca.certificate.cert.encode('utf-8'))
        the_ca_key_hash = ca_issuer_key_hash.finalize()
        issuer_name_hash = hashes.Hash(ocsp_req.hash_algorithm)
        issuer_name_hash.update(curr_issuer.subject.public_bytes(serialization.Encoding.DER))
        the_ca_name_hash = issuer_name_hash.finalize()
        if ocsp_req.issuer_key_hash == the_ca_key_hash:
            matched_ca = ca
#            print(f'matched with issuer_key_hash: {ca_issuer_key_hash} ocsp: {ocsp_req.issuer_key_hash}')
            issuer = curr_issuer
        elif ocsp_req.issuer_name_hash == the_ca_name_hash:
            matched_ca = ca
            issuer = curr_issuer
#            print(f'matched with issuer_key_hash: {the_ca_name_hash} ocsp: {ocsp_req.issuer_name_hash}')
        else:
            print(f'not matched with issuer_key_hash: {the_ca_name_hash} ocsp: {ocsp_req.issuer_name_hash}')

    responder = Ocsp.query.filter_by(ca_id=matched_ca.id).first()

    cert = Certificate.query.filter_by(certserialnumber=str(ocsp_req.serial_number)).first()
    certobj = load_pem_x509_certificate(cert.cert.encode('utf-8'))
    responder_cert = load_pem_x509_certificate(responder.cert.encode('utf-8'))
    responder_key = serialization.load_pem_private_key(responder.keys.key, responder.keys.password)

    builder = ocsp.OCSPResponseBuilder()

    ocspstatus = None
    revocation_time = None
    revocation_reason=None
    if cert.status == "active":
        ocspstatus = ocsp.OCSPCertStatus.GOOD
    else:
        ocspstatus = ocsp.OCSPCertStatus.REVOKED
        revocation_reason = x509.ReasonFlags.unspecified
        revocation_time = cert.revocation_time


    builder = builder.add_response(
        cert=certobj,
        issuer=issuer,
        algorithm=hashes.SHA256(),
        cert_status=ocspstatus,
        this_update=datetime.now(),
        next_update=datetime.now() + timedelta(seconds=600),
        revocation_time=revocation_time,
        revocation_reason=revocation_reason
    ).responder_id(
        ocsp.OCSPResponderEncoding.HASH, responder_cert
    )
    builder = builder.certificates([responder_cert])
    ocspnounce = ocsp_req.extensions.get_extension_for_class(x509.OCSPNonce)
    builder = builder.add_extension(ocspnounce.value, critical=False)

    response = builder.sign(responder_key, hashes.SHA256())
#    response.certificate_status

    resp = make_response(response.public_bytes(serialization.Encoding.DER))
    resp.mimetype = 'application/ocsp-response'

    finish_query = datetime.now()
    delta_t = finish_query - start_query
    delta_t_ms_str = round(delta_t.total_seconds() * 1000)
    from app.main.models import log
    log_row = {
        'title': 'ocsp reponse',
        'cert name': certobj.subject.rfc4514_string(),
        'cert serial': certobj.serial_number,
        'issuer name': issuer.subject.rfc4514_string(),
        'status': str(ocspstatus),
        'delta_t (ms)': delta_t_ms_str
        }
    log(log_row)
    # print(dumps(log_row))
    # print(f'''ocsp response
    # issuer name: {issuer.subject.rfc4514_string()}
    # cert name: {certobj.subject.rfc4514_string()}
    # cert serial: {certobj.serial_number}
    # status: str({ocspstatus})
    # delta_t (ms): {delta_t_ms_str}
    # ''')

    return resp
