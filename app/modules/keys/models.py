from app import db
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class Keys(db.Model):
    __tablename__ = "keys"
    __searchable__ = ['key']
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(10000))
    password = db.Column(db.String(100))

    def __repr__(self):
        return '<Keys {}>'.format(self.id)

    def to_dict(self):
        data = {
            'id': self.id,
            'key': self.key
            }
        return data
   
    def from_dict(self, data):
        for field in ['key']:
            setattr(self, field, data[field])

    def inventory_id(self):
        return '{}-{}'.format(self.__class__.__name__.lower(), self.id)

    def generate(self):

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.key = key
        return key

    def write_file(self, filename, password):

        with open(filename, "wb") as f:
            f.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            ))
