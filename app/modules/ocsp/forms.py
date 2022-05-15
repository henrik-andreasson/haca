from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired
from flask_babel import lazy_gettext as _l
from app.modules.safe.models import Safe, Compartment
from app.main.models import User, Location


class SafeForm(FlaskForm):
    name = StringField(_l('Name'), validators=[DataRequired()])
    location = SelectField(_l('Location'), coerce=int)
    status = StringField(_l('Name'), render_kw={'readonly': True})
    comment = TextAreaField(_l('Audit Comment'), render_kw={'readonly': True})
    submit = SubmitField(_l('Submit'))
    cancel = SubmitField(_l('Cancel'))
    delete = SubmitField(_l('Delete'))
    qrcode = SubmitField(_l('QR Code'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.location.choices = [(l.id, '{} / {} / {} / {}'.format(l.place, l.facillity, l.area, l.position)) for l in Location.query.order_by(Location.id).all()]


class AuditSafeForm(FlaskForm):
    safe = SelectField(_l('Location'), coerce=int)
    comment = TextAreaField(_l('Audit Comment'))
    approved = SubmitField(_l('Audit Approved'))
    failed = SubmitField(_l('Audit Failed'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.safe.choices = [(s.id, s.name) for s in Safe.query.order_by(Safe.name).all()]


class CompartmentForm(FlaskForm):
    name = StringField(_l('Name'), validators=[DataRequired()])
    safe = SelectField(_l('Safe'), coerce=int)
    user = SelectField(_l('User'), coerce=int)
    comment = TextAreaField(_l('Comment'))
    audit_date = StringField(_l('Audit date'), render_kw={'readonly': True})
    audit_status = StringField(_l('Audit status'), render_kw={'readonly': True})
    audit_comment = TextAreaField(_l('Audit Comment'), render_kw={'readonly': True})
    auditor = StringField(_l('Auditor'), render_kw={'readonly': True})
    submit = SubmitField(_l('Submit'))
    cancel = SubmitField(_l('Cancel'))
    delete = SubmitField(_l('Delete'))
    qrcode = SubmitField(_l('QR Code'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.safe.choices = [(s.id, s.name) for s in Safe.query.order_by(Safe.name).all()]
        self.user.choices = [(u.id, u.username) for u in User.query.order_by(User.username).all()]


class AuditCompartmentForm(FlaskForm):
    name = StringField(_l('Name'), validators=[DataRequired()], render_kw={'readonly': True})
    safe = StringField(_l('Safe'), render_kw={'readonly': True})
    user = StringField(_l('User'), render_kw={'readonly': True})
    comment = TextAreaField(_l('Audit Comment'))
    approved = SubmitField(_l('Audit Approved'))
    failed = SubmitField(_l('Audit Failed'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
