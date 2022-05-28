from flask import render_template, flash, redirect, url_for, request, \
    current_app
from flask_login import login_required
from app.main import bp
from app.main.models import Service
from app.modules.certificate.forms import CertificateForm, \
                                          FilterCertificateListForm, CsrForm
from app.modules.certificate.models import Certificate
from app.modules.ca.models import CertificationAuthority
from app.modules.keys.models import Keys
from flask_babel import _
from app import db
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from datetime import datetime
from cryptography.x509 import load_pem_x509_certificate


@bp.route('/cert/add', methods=['GET', 'POST'])
@login_required
def cert_add():
    if 'cancel' in request.form:
        return redirect(request.referrer)

    form = CertificateForm(formdata=request.form)

    if request.method == 'POST' and form.validate_on_submit():
        service = Service.query.get(form.service.data)
        if service is None:
            flash('Service is required')
            return redirect(request.referrer)
        ca = CertificationAuthority.query.get(form.ca.data)
        if ca is None:
            flash('CA is required')
            return redirect(request.referrer)

        # use ca to generate cert
        cert = Certificate(status=form.status.data,
                           validity_start=form.validity_start.data,
                           validity_end=form.validity_end.data,
                           comment=form.comment.data,
                           )
#        for field in ['name', 'userid', 'serial', 'orgunit', 'org', 'country']:
        certname_set = False
        if form.name.data is not None:
            cert.name = form.name.data
            certname_set = True
        if form.userid.data is not None:
            cert.userid = form.userid.data
            certname_set = True
        if form.serial.data is not None:
            cert.serial = form.serial.data
            certname_set = True
        if form.orgunit.data is not None:
            cert.orgunit = form.orgunit.data
            certname_set = True
        if form.org.data is not None:
            cert.org = form.org.data
            certname_set = True
        if form.country.data is not None:
            cert.country = form.country.data
            certname_set = True
        if form.profile.data is None:
            cert.profile = "server"
        else:
            cert.profile = form.profile.data

        if form.sandns.data is not None:
            cert.sandns = form.sandns.data

        # todo inline check, see auth username ...
        if certname_set is False:
            flash('At least one name field is required')
            return redirect(request.referrer)

        cert.service = service
        cert.ca = ca
        keys = Keys()
        signed = ca.create_cert(cert, b"foo123", b"foo123", keys)
        pemcert = signed.public_bytes(serialization.Encoding.PEM).decode()
#        txtcert = signed.public_bytes(serialization.Encoding.PEM).decode('UTF-8')
#        txtcert = txtcert.replace('-----BEGIN CERTIFICATE-----', '')
#        txtcert = txtcert.replace('-----END CERTIFICATE-----', '')
        certlist = pemcert.split('\n')
        cert.certserialnumber = str(signed.serial_number)
        cert.cert = pemcert
        db.session.add(cert)
        db.session.commit()
        # audit.auditlog_new_post('cert', original_data=cert.to_dict(), record_name=cert.name)
        flash(_(f'The new cert is now created {cert.name}!'))
        parse_cert = cert.parse_cert()

#        return redirect(url_for('main.index'))
        return render_template('cert.html', title=_('Certificate created'),
                               cert=cert, htmlcert=pemcert,
                               certlist=certlist,
                               pemkey=keys.keys.decode(),
                               parse_cert=parse_cert
                               )
    else:

        return render_template('cert.html', title=_('Add Certificate'),
                               form=form)


@bp.route('/cert/view/<int:id>', methods=['GET', 'POST'])
@login_required
def cert_view(id):

    cert = Certificate.query.get(id)

    if cert is None:
        render_template('cert.html', title=_('Certificate is not found'))

    pemcert = cert.cert
    certobj = load_pem_x509_certificate(pemcert.encode('utf-8'))
    cert.cert_obj = certobj
    parse_cert = cert.parse_cert()

    return render_template('cert.html', title=_('Certificate created'),
                           cert=cert, htmlcert=pemcert,
                           parse_cert=parse_cert
                           )


@bp.route('/cert/csr', methods=['GET', 'POST'])
@login_required
def cert_csr():
    if 'cancel' in request.form:
        return redirect(request.referrer)

    form = CsrForm(formdata=request.form)

    if request.method == 'POST' and form.validate_on_submit():
        service = Service.query.get(form.service.data)
        if service is None:
            flash('Service is required')
            return redirect(request.referrer)
        ca = CertificationAuthority.query.get(form.ca.data)
        if ca is None:
            flash('CA is required')
            return redirect(request.referrer)

        print(f'csr data: {form.csr.data}')
        csr = x509.load_pem_x509_csr(form.csr.data.encode('UTF-8'))
        cert = ca.create_cert_from_csr(b"foo123", csr,
                                       form.validity_start.data,
                                       form.validity_end.data)
        cert.service = service
        cert.ca = ca
        pemcert = cert.cert
        txtcert = cert.cert
        txtcert = txtcert.replace('-----BEGIN CERTIFICATE-----', '')
        txtcert = txtcert.replace('-----END CERTIFICATE-----', '')
        # audit.auditlog_new_post('cert', original_data=cert.to_dict(), record_name=cert.name)
        flash(_(f'The new cert is now created {cert.name}!'))

        return render_template('cert.html', title=_('Certificate created'),
                               cert=cert, htmlcert=pemcert,
                               txtcert=txtcert)
    else:

        return render_template('cert.html', title=_('Add Certificate'),
                               form=form)


@bp.route('/cert/edit/', methods=['GET', 'POST'])
@login_required
def cert_edit():

    id = request.args.get('id')

    if 'cancel' in request.form:
        return redirect(request.referrer)
    if 'logs' in request.form:
        return redirect(url_for('main.logs_list', module='firewall', module_id=id))
    if 'qrcode' in request.form:
        return redirect(url_for('main.firewall_qr', id=id))

    cert = Certificate.query.get(id)
#    original_data = cert.to_dict()

    if cert is None:
        render_template('cert.html', title=_('Certificate is not found'))

    form = CertificateForm(formdata=request.form, obj=cert)

    if request.method == 'POST' and form.validate_on_submit():

        # should only allow to update comment and status
        cert.status = form.status.data
        cert.comment = form.comment.data
        db.session.commit()
        # audit.auditlog_update_post('certificate', original_data=original_data, updated_data=cert.to_dict(), record_name=cert.name)
        flash(_('Your changes have been saved.'))

        return redirect(url_for('main.index'))

    else:
        form.service.data = cert.service_id
        form.ca.data = cert.ca_id
        return render_template('cert.html', title=_('Edit Certificate'),
                               form=form)


@bp.route('/cert/revoke/<int:id>', methods=['GET', 'POST'])
@login_required
def cert_revoke(id):

    cert = Certificate.query.get(id)
#    original_data = cert.to_dict()

    if cert is None:
        render_template('cert.html', title=_('Certificate is not found'))

    cert.status = "revoked"
    cert.revocation_time = datetime.now()
    db.session.commit()
    # audit.auditlog_update_post('certificate', original_data=original_data, updated_data=cert.to_dict(), record_name=cert.name)
    flash(_(f'Cert: {cert.name} serial: {cert.certserialnumber} have been revoked.'))

    return render_template('cert.html', title=_('Certificate revoked'))


@bp.route('/cert/list/', methods=['GET', 'POST'])
@login_required
def cert_list():

    page = request.args.get('page', 1, type=int)
    service_name = request.args.get('service')
    service = Service.query.filter_by(name=service_name).first()

    form = FilterCertificateListForm()
    certs = None
    if request.method == 'POST' and form.validate_on_submit():
        if service is not None:
            certs = Certificate.query.filter_by(service_id=service.id).paginate(
                page, current_app.config['POSTS_PER_PAGE'], False)
        else:
            certs = Certificate.query.order_by(Certificate.name).paginate(
                page, current_app.config['POSTS_PER_PAGE'], False)
    else:
        certs = Certificate.query.order_by(Certificate.name).paginate(
            page, current_app.config['POSTS_PER_PAGE'], False)

    next_url = url_for('main.cert_list', page=certs.next_num) \
        if certs.has_next else None
    prev_url = url_for('main.cert_list', page=certs.prev_num) \
        if certs.has_prev else None

    return render_template('cert.html', title=_('Certificate'),
                           certs=certs.items, next_url=next_url,
                           prev_url=prev_url, form=form)
