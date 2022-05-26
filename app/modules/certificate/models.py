from app import db
from datetime import datetime
from cryptography import x509
import binascii
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes


def format_signature(signature=None):
    import re
    siglist = re.findall('..', binascii.hexlify(signature).decode())
    signature = ":".join(siglist)
    start = 0
    end = 54
    siglist2 = []
    siglen = len(signature)
    while end < siglen:
        siglist2.append(signature[start:end])
        start += 54
        end += 54
        if end > siglen:
            siglist2.append(signature[start:siglen])
    signature2 = "\n".join(siglist2)
    return signature2


def format_modulus(modulus=None):
    import re
    hex_mod = hex(modulus)
    hex_mod = re.sub('0x', '', hex_mod)
    moduluslist = re.findall('..', hex_mod)
    modulus2 = ":".join(moduluslist)
    start = 0
    end = 45
    moduluslist2 = []
    moduluslen = len(modulus2)
    while end < moduluslen:
        moduluslist2.append(modulus2[start:end])
        start += 45
        end += 45
        if end > moduluslen:
            moduluslist2.append(modulus2[start:moduluslen])
    modulus3 = "\n".join(moduluslist2)
    return modulus3


def format_public_key(public_key=None):
    public_key2 = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1).decode()
    public_key2 = public_key2.replace('-----BEGIN RSA PUBLIC KEY-----\n', '')
    public_key2 = public_key2.replace('-----END RSA PUBLIC KEY-----\n', '')
    public_key2 = public_key2.replace(' ', '')
    return public_key2


class Certificate(db.Model):
    __tablename__ = "certificate"
    __searchable__ = ['name', 'comment', 'status', 'serial']

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    userid = db.Column(db.String(255))
    serial = db.Column(db.String(255))
    orgunit = db.Column(db.String(255))
    org = db.Column(db.String(255))
    country = db.Column(db.String(255))
    sandns = db.Column(db.String(4000))
    ca = db.relationship('CertificationAuthority', foreign_keys='Certificate.ca_id')
    ca_id = db.Column(db.Integer, db.ForeignKey('certification_authority.id'))
    service = db.relationship('Service')
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'))
    validity_start = db.Column(db.DateTime)
    validity_end = db.Column(db.DateTime)
    cert = db.Column(db.String(2000))
    certserialnumber = db.Column(db.String(100))
    cert_obj = x509
    status = db.Column(db.String(140))
    revocation_time = db.Column(db.DateTime)
    comment = db.Column(db.String(2000))

    def __repr__(self):
        return '<Switch {}>'.format(self.name)

    def inventory_id(self):
        return '{}-{}'.format(self.__class__.__name__.lower(), self.id)

    def to_dict(self):
        data = {
            'id': self.id,
            'name': self.name,
            'serial': self.cert_obj.serialnumber,
            'service_id': self.service_id,
            'status': self.status,
            'validity_start': self.validity_start,
            'validity_end': self.validity_end,
            'cert': self.cert,
            'comment': self.comment,
            }
        return data

    def from_dict(self, data):
        from app.main.models import Service

        for field in ['name', 'serial', 'status']:
            if field not in data:
                return {'msg': "must include field: %s" % field, 'success': False}
            else:
                setattr(self, field, data[field])

        for field in ['validity_start', 'validity_end']:
            if field not in data:
                return {'msg': "must include field: %s" % field, 'success': False}
            else:
                date = datetime.strptime(data[field], "%Y-%m-%d")
                setattr(self, field, date)

        if 'service_id' in data:
            service = Service.query.get(data['service_id'])
        elif 'service_name' in data:
            service = Service.query.filter_by(name=data['service_name']).first()

        if service is None:
            return {'msg': "no service found via service_name nor id", 'success': False}
        else:
            setattr(self, 'service_id', service.id)

        return {'msg': "object loaded ok", 'success': True}

    def parse_cert(self):

        data = {
            'id': self.id,
            'subject_dn': self.cert_obj.subject.rfc4514_string(),
            'issuer_dn': self.cert_obj.issuer.rfc4514_string(),
            'serial_number': hex(self.cert_obj.serial_number),
            'not_valid_before': self.cert_obj.not_valid_before,
            'not_valid_after': self.cert_obj.not_valid_after,
            'signature_hash_algorithm': self.cert_obj.signature_hash_algorithm.name,
            'version': self.cert_obj.version,
            'fingerprint':  binascii.hexlify(self.cert_obj.fingerprint(hashes.SHA256())).decode(),
            'public_key': format_public_key(self.cert_obj.public_key()),
            'public_key_openssh': self.cert_obj.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode(),
            'public_modulus': format_modulus(self.cert_obj.public_key().public_numbers().n),
            'public_exponent': self.cert_obj.public_key().public_numbers().e,
            'signature': format_signature(self.cert_obj.signature),
            'key_size': self.cert_obj.public_key().key_size,
            }

        for ext in self.cert_obj.extensions:
            print(f'oid: {ext.oid} value: {ext.value} is critical: {ext.critical}')

        return data
