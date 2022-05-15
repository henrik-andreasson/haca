from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, TextAreaField, DateTimeField
from wtforms.validators import DataRequired
from flask_babel import lazy_gettext as _l
from datetime import datetime
from app.main.models import Service
from app.modules.ca.models import CertificationAuthority


class CAForm(FlaskForm):
    name = StringField(_l('Name'), validators=[DataRequired()])
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
                                 default=datetime.now())
    comment = TextAreaField(_l('Comment'))
    crl = StringField(_l('CRL CDP'))
    ocsp = StringField(_l('OCSP URL'))

    submit = SubmitField(_l('Submit'))
    cancel = SubmitField(_l('Cancel'))
    delete = SubmitField(_l('Delete'))
    logs = SubmitField(_l('Logs'))
    ports = SubmitField(_l('Firewall Ports'))
    qrcode = SubmitField(_l('QR Code'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.service.choices = [(s.id, s.name) for s in Service.query.order_by(Service.name).all()]
        cas = CertificationAuthority.query.order_by(CertificationAuthority.name).all()
        if len(cas) <= 0:
            self.ca.choices = []
            self.ca.choices.insert(0, (-1, _l('Self Signed')))
        else:
            self.ca.choices = [(c.id, c.name) for c in cas]
            self.ca.choices.insert(0, (-1, _l('Self Signed')))
#TODO        self.ca.choices.insert(0, (-1, _l('External')))


class FilterCAListForm(FlaskForm):
    service = SelectField(_l('Service'), coerce=int)
    status = SelectField(_l('Status'))
    submit = SubmitField(_l('Filter List'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.service.choices = [(s.id, s.name) for s in Service.query.order_by(Service.name).all()]
        self.service.choices.insert(0, (-1, _l('All')))
        self.status.choices = [('all', 'All'),
                               ('active', 'Active'),
                               ('revoked', 'Revoked'),
                               ('on-hold', 'On Hold'),
                               ('unknown', 'Unknown')]
