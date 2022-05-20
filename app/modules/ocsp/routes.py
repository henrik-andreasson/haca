from flask import render_template, flash, redirect, url_for, request, \
  current_app, make_response
from flask_login import login_required
from app import db
from app.main import bp
from app.modules.ocsp.models import Ocsp
from app.modules.ocsp.forms import OcspForm, FilterOcspListForm
from flask_babel import _
from sqlalchemy import desc, asc
from app.modules.ca.models import CertificationAuthority
from app.modules.keys.models import Keys
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp


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


@bp.route('/ocsp/query/', methods=['GET', 'POST'])
def ocsp_query():

    length = int(request.headers['content-length'])
    if length > 10000:
        print(f'to much data {length}')
        return None

    data = request.get_data(cache=False, as_text=False, parse_form_data=False)
    import pprint
    pp = pprint.PrettyPrinter()
    pp.pprint(data)
    ocsp_req = ocsp.load_der_ocsp_request(data)
    print(f'''
ocsp req serial:  {ocsp_req.serial_number}
issuer_key hash:  {ocsp_req.issuer_key_hash}
issuer_name_hash: {ocsp_req.issuer_name_hash}
hash_algorithm:   {ocsp_req.issuer_name_hash}
''')
    for e in ocsp_req.extensions:
        print(f'extensions:       {e}')

    responder = Ocsp.query.order_by(Ocsp.validity_end).first()
    # loop the cert and select the best

    import datetime
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import load_pem_x509_certificate

    pem_issuer = b'''-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIUNhLv1R6WGrrAebORpBxc0hqW27cwDQYJKoZIhvcNAQEL
BQAwLDELMAkGA1UEBhMCU0UxDzANBgNVBAoMBlRlc3RDQTEMMAoGA1UEAwwDYmJi
MB4XDTIyMDUxOTAwMDAwMFoXDTMyMDUxOTAwMDAwMFowLDELMAkGA1UEBhMCU0Ux
DzANBgNVBAoMBlRlc3RDQTEMMAoGA1UEAwwDYmJiMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAysy7tW73d33//1Y8W9mQ7GOPGWg3B0ZS9UEDAdBrfQY2
bOLcTZB3Luy3etRDl+0rESXq4D1EFJL9Sqf6lPsDXp5xbDj8D4fOxzsUP26C7FSQ
i/RDTdcd9TruQbnUIwXiERQZOBpMAvugbbGJYdoA0vrMRKT1jUeyemLHpy17/JXc
0DCKWQqfGRPz57zaTEtVo77ZZk6x/KmAEgxzrpESmUCohgUvtwmGQQ/d7OPNfVdK
V+uAQrWemEv5LPmXBixE7lkGqgfpTAsHexy019Hrb6prY6GyiKgsbYAORkdQ6IbG
a0XmbyPbdOrsrugS/yKrQ6mpAAZdVLKb4E+XDQFpIQIDAQABoxYwFDASBgNVHRMB
Af8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQDJGXuE27BnnpZ+GL7x0Yw3
FetPKrMK22QHFat0hjxsSi+Y8Qgrh7i3nrIkB8vxz9uLTYiLnoGxFRYl02l8L3Bl
m5UzFf7dHcWPgl11CRbR8QlUDst0Y7vci2tiiSUVv1txgBqn6jQ64h8nSver8IzK
ZOuvbdbl4i2vKbnNWWE7yE3ZsZACsshqvhGtfVXO+yg7CCb1iLYFbN6fLDIuOXll
BUnzi2WiklbimWCL25udybWLzUfAJKIXCqa16pmxjQ1IMMEWluXzLqkADA2Qi9BR
y+wONYFnghD55ehIiWvkl0EonWllR8zaoir7zXbD+BCH/BLdD98ZCdA8tU1PPRym
-----END CERTIFICATE-----'''

    pem_cert = b'''-----BEGIN CERTIFICATE-----
MIID8jCCAtqgAwIBAgIUX7iRH0iV9Blhg/nwLNxR2cYqDBMwDQYJKoZIhvcNAQEL
BQAwLDELMAkGA1UEBhMCU0UxDzANBgNVBAoMBlRlc3RDQTEMMAoGA1UEAwwDYmJi
MB4XDTIyMDUxOTAwMDAwMFoXDTIzMDUyMDAwMDAwMFowUjEQMA4GA1UEAwwHYmJi
YmJiYjEQMA4GCgmSJomT8ixkAQEMADEJMAcGA1UEBRMAMQkwBwYDVQQLDAAxCTAH
BgNVBAoMADELMAkGA1UEBhMCU0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDPTX4LJizhEDAqxeJrOVmtvQmr3LW4SGKxnFs/g9kxcCay8L9g3fkemjtN
wF9pxllZtGpQOHDZ9IwefU93VI9GHL3V8nQfVQxXO8XC5qdmp+2yJVtjjHt5mfG3
h44s5tJDinxFOaIaRn4sK2A+/OUD6nro26mBIdiiRB27Vaq8WCTtWFvS3WGf+hMC
ycheLATP9XvplxVXeqMiUJDTyNBYsAd6l3SwY2kCZpqCyk8Ybt1JRw9S6Wuqn2v3
2Pd2WU3Rps/ZhSt6ST7Q8h1hb/dxLQmA2VtWg9LjkpWj+BdcQauSAoelikFCLdG7
xJrtD/SnYr+gyq16TJuIGlHeOIqLAgMBAAGjgeUwgeIwFAYDVR0RBA0wC4IAggdi
YmJiYmJiMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIFoDAu
BgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vc2VydmVyLmNvbS9jcmwvYmJiLmNybDAy
BggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9zZXJ2ZXIuY29tL29j
c3AwHwYDVR0jBBgwFoAU6F9s4wc3tloigVlR+lyvpClQoiowHQYDVR0OBBYEFFCP
OjVIEN1Tdy+xF2O1ExgAzq/IMA0GCSqGSIb3DQEBCwUAA4IBAQAEI5/paU7d/GT8
sJFTp+IPtkQEg925WnvmV/5u6fG+Ym2/KnHqjVAKAXFJoES+2XsjW+lMmru7nSMF
dW6v7ySVg1yT+oerUgMJkWI5VW9bhqw62msKIsPUqCyWNfwmy/WWTjrCfhL/jK7x
MgH9L317WcEFK+0I0X3d42tojtxro/Ms6dFwyZW2Ur5nmObB9CGdgTYga/jlLfGL
FN0Fi22WxuYSD2Ua9go7Bn1XGm5+qtuDAQUHnl5WX3CZ32bMBKvLvfgvsIe53x0O
yMEzX5FqzK3ndBB8AbRznj68sEpDQyCKLapuLG5smRa2vQIPimP0uLALruZ7hbiW
XFMnY/cC
-----END CERTIFICATE-----'''

    cert = load_pem_x509_certificate(pem_cert)
    issuer = load_pem_x509_certificate(pem_issuer)
    responder_cert = load_pem_x509_certificate(responder.cert.encode('utf-8'))
    responder_key = serialization.load_pem_private_key(responder.keys.key, responder.keys.password)

    builder = ocsp.OCSPResponseBuilder()

    builder = builder.add_response(
        cert=cert,
        issuer=issuer,
        algorithm=hashes.SHA256(),
        cert_status=ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.now(),
        next_update=datetime.datetime.now(),
        revocation_time=None,
        revocation_reason=None
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
    return resp
