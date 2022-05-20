from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, TextAreaField, DateTimeField
from wtforms.validators import DataRequired
from flask_babel import lazy_gettext as _l
from app.modules.ca.models import CertificationAuthority
from datetime import datetime, timedelta


class OcspForm(FlaskForm):
    name = StringField(_l('Common Name (CN)'), validators=[DataRequired()])
    serial = StringField(_l('Serial Number (SN)'))
    orgunit = StringField(_l('Organisational Unit (OU)'))
    org = StringField(_l('Organisation (O)'))
    country = StringField(_l('Country (C)'))

    status = SelectField(_l('Status'), choices=[('active', 'Active'),
                                                ('revoked', 'Revoked'),
                                                ('on-hold', 'On Hold'),
                                                ('unknown', 'Unknown')])
    ca = SelectField(_l('CA'), coerce=int)
    validity_start = DateTimeField(_l('Validity Start'), validators=[DataRequired()],
                                   format='%Y-%m-%d', default=datetime.now())
    validity_end = DateTimeField(_l('Validity End'),
                                 validators=[DataRequired()], format='%Y-%m-%d',
                                 default=datetime.now() + timedelta(days=366))

    comment = TextAreaField(_l('Audit Comment'), render_kw={'readonly': True})
    submit = SubmitField(_l('Submit'))
    cancel = SubmitField(_l('Cancel'))
    delete = SubmitField(_l('Delete'))
    qrcode = SubmitField(_l('QR Code'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ca.choices = [(c.id, c.name) for c in CertificationAuthority.query.order_by(CertificationAuthority.name).all()]


class FilterOcspListForm(FlaskForm):
    ca = SelectField(_l('CA'), coerce=int)
    status = SelectField(_l('Status'), choices=[('active', 'Active'),
                                                ('revoked', 'Revoked'),
                                                ('on-hold', 'On Hold'),
                                                ('unknown', 'Unknown')])
    submit = SubmitField(_l('Filter List'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ca.choices = [(c.id, c.name) for c in CertificationAuthority.query.order_by(CertificationAuthority.name).all()]
