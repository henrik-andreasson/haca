from flask import render_template, flash, redirect, url_for, request, \
    current_app, session, send_file
from flask_login import login_required
from app import db
from app.main import bp
from flask_babel import _


@bp.route('/qr/image', methods=['GET'])
@login_required
def qr_img():

    string = request.args.get('string')
    if string is None:
        flash(_('QR Code failed, no input!'))
        return redirect(url_for('main.index'))
    else:
        print(f'string: {string}')

    import qrcode
    qr = qrcode.QRCode(version=1,box_size=10,border=5)
    qr.add_data(string)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    import io
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)

    return send_file(buf, mimetype='image/png')
