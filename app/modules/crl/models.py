from app import db
from cryptography import x509
from cryptography.x509 import CertificateRevocationList
from cryptography.hazmat.primitives import serialization
from app.main.models import PaginatedAPIMixin


class Crl(PaginatedAPIMixin, db.Model):
    __tablename__ = "crl"
    __searchable__ = []
    id = db.Column(db.Integer, primary_key=True)
    ca = db.relationship('CertificationAuthority', foreign_keys='Crl.ca_id')
    ca_id = db.Column(db.Integer, db.ForeignKey('certification_authority.id'))
    crl = CertificateRevocationList
    validity_start = db.Column(db.DateTime)
    validity_end = db.Column(db.DateTime)
    pem = db.Column(db.String(2000))

    def __repr__(self):
        return '<CRL no: {}>'.format(self.id)

    def to_dict(self):
        data = {
            'id': self.id,
            'ca_id': self.ca_id,
            'validity_start': self.validity_start,
            'validity_end': self.validity_end,
            'crl': self.pem
            }
        return data

    def from_dict(self, data):
        for field in ['ca_id']:
            if field not in data:
                return {'msg': "must include field: %s" % field, 'success': False}
            else:
                setattr(self, field, data[field])

        if 'crl' in data:
            setattr(self, 'crl', x509.load_pem_x509_crl(data['crl']))
        else:
            return {'msg': "crl mustbe an argument", 'success': False}

        return {'msg': "object loaded ok", 'success': True}

    def inventory_id(self):
        return '{}-{}'.format(self.__class__.__name__.lower(), self.id)
