from app import db


class Ocsp(db.Model):
    __tablename__ = "ocsp"
    __searchable__ = ['name', 'status', 'comment']
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), unique=True)
    userid = db.Column(db.String(255))
    serial = db.Column(db.String(255))
    orgunit = db.Column(db.String(255))
    org = db.Column(db.String(255))
    country = db.Column(db.String(255))
    sandns = db.Column(db.String(4000))
    ca = db.relationship('CertificationAuthority', foreign_keys='Ocsp.ca_id')
    ca_id = db.Column(db.Integer, db.ForeignKey('certification_authority.id'))
    keys = db.relationship('Keys')
    keys_id = db.Column(db.Integer, db.ForeignKey('keys.id'))
    cert = db.Column(db.String(2000))
    validity_start = db.Column(db.DateTime)
    validity_end = db.Column(db.DateTime)
    status = db.Column(db.String(20))
    comment = db.Column(db.String(255))

    def __repr__(self):
        return '<Safe {}>'.format(self.name)

    def to_dict(self):
        data = {
            'id': self.id,
            'name': self.name,
            'status': self.status,
            'certificate_id': self.certificate_id,
            'keys_id': self.keys_id,
            'ca_id': self.ca_id,
            'comment': self.comment
            }
        return data

    def from_dict(self, data, new_work=False):

        for field in ['name', 'ca_id', 'status', 'comment', 'certificate_id', 'keys_id']:
            if field in data:
                setattr(self, field, data[field])

    def inventory_id(self):
        return '{}-{}'.format(self.__class__.__name__.lower(), self.id)
