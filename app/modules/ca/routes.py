from flask import render_template, flash, redirect, url_for, request, \
    current_app
from flask_login import login_required
from app import db
from app.main import bp
from app.main.models import Service
from flask_babel import _
# from app.modules.ca.forms import CAForm
from app.modules.certificate.models import Certificate
from app.modules.ca.models import CertificationAuthority
from app.modules.ca.forms import FilterCAListForm, \
                                 CAForm
# from cryptography.hazmat.primitives import serialization


@bp.route('/ca/add', methods=['GET', 'POST'])
@login_required
def ca_add():
    if 'cancel' in request.form:
        return redirect(request.referrer)

    form = CAForm(formdata=request.form)

    ip = request.args.get('ip')
    if ip:
        form.ipaddress.data = ip

    if request.method == 'POST' and form.validate_on_submit():
        service = Service.query.get(form.service.data)
        if service is None:
            flash('Service is required')
            return redirect(request.referrer)

        if form.ca.data == -1:
            # -1 == self signed
            ca_id = form.ca.data
        else:
            ca = CertificationAuthority.query.get(form.ca.data)
            if ca is None:
                flash('CA not found')
                return redirect(request.referrer)
            ca_id = ca.id
        cert = Certificate(name=form.name.data,
                           validity_start=form.validity_start.data,
                           validity_end=form.validity_end.data,
                           status="active"
                           )
        ca = CertificationAuthority(name=form.name.data,
                                    ca_id=ca_id,
                                    comment=form.comment.data,
                                    crl_cdp=form.crl.data,
                                    ocsp_url=form.ocsp.data
                            )
        ca.service = service
        ca.create_ca(cert, passphrase=b"foo123")

        db.session.add(ca)
        db.session.commit()
         #  audit.auditlog_new_post('ca', original_data=ca.to_dict(), record_name=ca.name)
        flash(_('New ca is now posted!'))

        return redirect(url_for('main.index'))

    else:

        return render_template('ca.html', title=_('Add CertificationAuthority'),
                               form=form)


@bp.route('/ca/edit/', methods=['GET', 'POST'])
@login_required
def ca_edit():

    id = request.args.get('id')

    if 'cancel' in request.form:
        return redirect(request.referrer)
    if 'delete' in request.form:
        return redirect(url_for('main.ca_delete', ca=id))
    if 'logs' in request.form:
        return redirect(url_for('main.logs_list', module='ca', module_id=id))
    if 'qrcode' in request.form:
        return redirect(url_for('main.ca_qr', id=id))

    ca = CertificationAuthority.query.get(id)
#    original_data = ca.to_dict()

    if ca is None:
        render_template('service.html', title=_('CertificationAuthority is not defined'))

    form = CAForm(formdata=request.form, obj=ca)

    if request.method == 'POST' and form.validate_on_submit():

        ca.name = form.name.data
        ca.alias = form.alias.data
        ca.ipaddress = form.ipaddress.data
        ca.serial = form.serial.data
        ca.manufacturer = form.manufacturer.data
        ca.model = form.model.data
        ca.rack_id = form.rack.data
        ca.service_id = form.service.data
        ca.status = form.status.data
        ca.support_start = form.support_start.data
        ca.support_end = form.support_end.data
        ca.rack_position = form.rack_position.data
        ca.comment = form.comment.data
        db.session.commit()
         #  audit.auditlog_update_post('ca', original_data=original_data, updated_data=ca.to_dict(), record_name=ca.name)
        flash(_('Your changes have been saved.'))

        return redirect(url_for('main.index'))

    else:
        form.service.data = ca.service_id
        return render_template('ca.html', title=_('Edit CertificationAuthority'),
                               form=form)


@bp.route('/ca/list/', methods=['GET', 'POST'])
@login_required
def ca_list():

    page = request.args.get('page', 1, type=int)


    form = FilterCAListForm()

    if request.method == 'POST' and form.validate_on_submit():
        status = form.status.data
        service = Service.query.get(form.service.data)

        # if status is not None:
        #     # TODO
        #     cas = CertificationAuthority.query.filter_by(status=status).all()
        if service is not None:
            cas = CertificationAuthority.query.filter_by(service_id=service.id).paginate(
                page = page, per_page = current_app.config['POSTS_PER_PAGE'])
        else:
            cas = CertificationAuthority.query.order_by(CertificationAuthority.name).paginate(
                page = page, per_page = current_app.config['POSTS_PER_PAGE'])

    else:
        cas = CertificationAuthority.query.order_by(CertificationAuthority.name).paginate(
            page = page, per_page = current_app.config['POSTS_PER_PAGE'])

    next_url = url_for('main.ca_list', page=cas.next_num) \
        if cas.has_next else None
    prev_url = url_for('main.ca_list', page=cas.prev_num) \
        if cas.has_prev else None

    return render_template('ca.html', title=_('CertificationAuthority'),
                           cas=cas.items, next_url=next_url,
                           prev_url=prev_url, form=form)


@bp.route('/ca/delete/', methods=['GET', 'POST'])
@login_required
def ca_delete():

    caid = request.args.get('ca')
    ca = CertificationAuthority.query.get(caid)

    if ca is None:
        flash(_('CertificationAuthority was not deleted, id not found!'))
        return redirect(url_for('main.index'))

    deleted_msg = 'CertificationAuthority deleted: %s\n' % (ca.name)
    flash(deleted_msg)
    db.session.delete(ca)
    db.session.commit()
     #  audit.auditlog_delete_post('ca', data=ca.to_dict(), record_name=ca.name)

    return redirect(url_for('main.index'))


@bp.route('/ca/qr/<int:id>', methods=['GET'])
@login_required
def ca_qr(id):
    if id is None:
        flash(_('CertificationAuthority was not found, id not found!'))
        return redirect(url_for('main.index'))

    ca=None
    from app.modules.ca.models import CertificationAuthority
    ca = CertificationAuthority.query.get(id)

    if ca is None:
        flash(_('CertificationAuthority was not found, id not found!'))
        return redirect(url_for('main.index'))

    qr_data = url_for("main.ca_edit", ca=ca.id, _external=True)
    return render_template('ca_qr.html', title=_('QR Code'),
                           ca=ca, qr_data=qr_data)
