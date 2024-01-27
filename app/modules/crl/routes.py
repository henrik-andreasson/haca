from flask import render_template, flash, redirect, url_for, request, current_app, make_response
from flask_login import login_required, current_user
from app import db
from app.main import bp
from flask_babel import _
from app.modules.crl.models import Crl
from app.modules.crl.forms import CRLForm
from app.modules.ca.models import CertificationAuthority
from cryptography.hazmat.primitives import serialization
from cryptography import x509


@bp.route('/crl/add', methods=['GET', 'POST'])
@login_required
def crl_add():
    if 'cancel' in request.form:
        return redirect(request.referrer)

    form = CRLForm(formdata=request.form)

    if request.method == 'POST' and form.validate_on_submit():
        ca = CertificationAuthority.query.get(form.ca.data)
        if ca is None:
            flash('CA is required')
            return redirect(request.referrer)

        crl = Crl(validity_start=form.validity_start.data,
                  validity_end=form.validity_end.data)
        crl_obj = ca.create_crl(crl, b"foo123")

        crl.crl = crl_obj
        pemcrl = crl.crl.public_bytes(serialization.Encoding.PEM).decode()
        crl.pem = pemcrl
        crl.ca = ca
        db.session.add(crl)
        db.session.commit()

        flash(_('New CRL is now posted!'))

        return render_template('crl.html', title=_('CRL'),
                               crl=crl, pemcrl=pemcrl)
    else:

        return render_template('crl.html', title=_('CRL'),
                               form=form)


@bp.route('/crl/list/', methods=['GET', 'POST'])
@login_required
def crl_list():

    page = request.args.get('page', 1, type=int)

    crls = Crl.query.order_by(Crl.id).paginate(
        page = page, per_page = current_app.config['POSTS_PER_PAGE'])

    next_url = url_for('main.rack_list', page=crls.next_num) \
        if crls.has_next else None
    prev_url = url_for('main.rack_list', page=crls.prev_num) \
        if crls.has_prev else None

    return render_template('crl.html', title=_('CRL'),
                           crls=crls.items, next_url=next_url,
                           prev_url=prev_url)


@bp.route('/crl/info/<int:id>', methods=['GET', 'POST'])
@login_required
def crl_info(id):

    if id is None:
        flash(_('CRL id missing!'))
        return redirect(request.referrer)

    crl = Crl.query.get(id)
    if crl is None:
        flash(_('CRL missing!'))
        return redirect(request.referrer)

    return render_template('crl.html', title=_('CRL'),
                           crl=crl)


@bp.route('/crl/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def crl_delete(id):

    if id is None:
        flash(_('CRL id missing!'))
        return redirect(request.referrer)

    crl = Crl.query.get(id)
    if crl is None:
        flash(_('CRL missing!'))
        return redirect(request.referrer)

    flash(_(f'Deleting CRL:{crl.id} / {crl.ca.name}!'))
    db.session.delete(crl)
    db.session.commit()

    return redirect(request.referrer)


@bp.route('/crl/get/<int:id>', methods=['GET', 'POST'])
@login_required
def crl_get(id):

    if id is None:
        flash(_('CRL id missing!'))
        return redirect(request.referrer)

    crl = Crl.query.get(id)
    if crl is None:
        flash(_('CRL missing!'))
        return redirect(request.referrer)

    print(f'crldata: {crl.pem}')
    crlobj = x509.load_pem_x509_crl(bytes(crl.pem, 'utf-8'))
    dercrl = crlobj.public_bytes(serialization.Encoding.DER)

    resp = make_response(dercrl)
    resp.mimetype = 'application/pkix-crl'
    resp.headers = {"Content-Disposition": "attachment;filename={}.crl".format(crl.ca.name)}
    return resp
