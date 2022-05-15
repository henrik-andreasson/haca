from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, TextAreaField, DateTimeField
from wtforms.validators import DataRequired
from flask_babel import lazy_gettext as _l
from datetime import datetime, timedelta
from app.main.models import Service
from app.modules.ca.models import CertificationAuthority


class CertificateForm(FlaskForm):
    profile = SelectField(_l('Profile'), choices=[('server', 'Server'),
                                                  ('client', 'Client'),
                                                  ('server-client', 'Server+Client'),
                                                  ('digsig', 'Digital Signature')])

    name = StringField(_l('Common Name (CN)'), validators=[DataRequired()])
    sandns = StringField(_l('SAN DNS (fqdn,fqdn,...)'))
    userid = StringField(_l(' UserID (UID)'))
    serial = StringField(_l('Serial Number (SN)'))
    orgunit = StringField(_l('Organisational Unit (OU)'))
    org = StringField(_l('Organisation (O)'))
    country = StringField(_l('Country (C)'))
    ca = SelectField(_l('CA'), coerce=int)
    service = SelectField(_l('Service'), coerce=int)
    status = SelectField(_l('Status'), choices=[('active', 'Active'),
                                                ('revoked', 'Revoked'),
                                                ('on-hold', 'On Hold'),
                                                ('unknown', 'Unknown')])
    validity_start = DateTimeField(_l('Validity Start'), validators=[DataRequired()],
                                   format='%Y-%m-%d', default=datetime.now())
    validity_end = DateTimeField(_l('Validity End'),
                                 validators=[DataRequired()], format='%Y-%m-%d',
                                 default=datetime.now() + timedelta(days=366))
    comment = TextAreaField(_l('Comment'))
    submit = SubmitField(_l('Submit'))
    cancel = SubmitField(_l('Cancel'))
    logs = SubmitField(_l('Logs'))
    qrcode = SubmitField(_l('QR Code'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.service.choices = [(s.id, s.name) for s in Service.query.order_by(Service.name).all()]
        self.ca.choices = [(c.id, c.name) for c in CertificationAuthority.query.order_by(CertificationAuthority.name).all()]


class CsrForm(FlaskForm):
    csr = TextAreaField(_l('CSR'), validators=[DataRequired()], render_kw={"rows": 20})
    ca = SelectField(_l('CA'), coerce=int)
    service = SelectField(_l('Service'), coerce=int)
    status = SelectField(_l('Status'), choices=[('active', 'Active'),
                                                ('revoked', 'Revoked'),
                                                ('on-hold', 'On Hold'),
                                                ('unknown', 'Unknown')])
    profile = SelectField(_l('Profile'), choices=[('server', 'Server'),
                                                  ('client', 'Client'),
                                                  ('server-client', 'Server+Client'),
                                                  ('digsig', 'Digital Signature')])
    validity_start = DateTimeField(_l('Validity Start'), validators=[DataRequired()],
                                   format='%Y-%m-%d', default=datetime.now())
    validity_end = DateTimeField(_l('Validity End'),
                                 validators=[DataRequired()], format='%Y-%m-%d',
                                 default=datetime.now() + timedelta(days=366))
    comment = TextAreaField(_l('Comment'))
    submit = SubmitField(_l('Submit'))
    cancel = SubmitField(_l('Cancel'))
    logs = SubmitField(_l('Logs'))
    qrcode = SubmitField(_l('QR Code'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.service.choices = [(s.id, s.name) for s in Service.query.order_by(Service.name).all()]
        self.ca.choices = [(c.id, c.name) for c in CertificationAuthority.query.order_by(CertificationAuthority.name).all()]


class FilterCertificateListForm(FlaskForm):
    service = SelectField(_l('Service'), coerce=int)
    status = SelectField(_l('Status'))
    submit = SubmitField(_l('Filter List'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.service.choices = [(s.id, s.name) for s in Service.query.order_by(Service.name).all()]
        self.service.choices.insert(0, (-1, _l('None')))
        self.status.choices = [('active', 'Active'),
                               ('revoked', 'Revoked'),
                               ('on-hold', 'On Hold'),
                               ('unknown', 'Unknown')]
