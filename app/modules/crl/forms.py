from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, TextAreaField, DateTimeField
from wtforms.validators import DataRequired
from flask_babel import lazy_gettext as _l
from app.modules.ca.models import CertificationAuthority
from datetime import datetime, timedelta


class CRLForm(FlaskForm):
    ca = SelectField(_l('CA'), coerce=int)
    validity_start = DateTimeField(_l('Validity Start'), validators=[DataRequired()],
                                   format='%Y-%m-%d', default=datetime.now())
    validity_end = DateTimeField(_l('Validity End'),
                                 validators=[DataRequired()], format='%Y-%m-%d',
                                 default=datetime.now() + timedelta(days=5))

    submit = SubmitField(_l('Submit'))
    cancel = SubmitField(_l('Cancel'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ca.choices = [(c.id, c.name) for c in CertificationAuthority.query.order_by(CertificationAuthority.name).all()]
