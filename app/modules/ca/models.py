from app import db
from app.modules.keys.models import Keys
from app.modules.certificate.models import Certificate
from app.main.models import PaginatedAPIMixin


class CertificationAuthority(PaginatedAPIMixin, db.Model):
    __tablename__ = "certification_authority"
    __searchable__ = ['name', 'comment']

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(2000))
    certificate = db.relationship('Certificate', foreign_keys='CertificationAuthority.certificate_id')
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificate.id'))
    ca = db.relationship('CertificationAuthority', foreign_keys='CertificationAuthority.ca_id')
    ca_id = db.Column(db.Integer, db.ForeignKey('certification_authority.id'))

    keys = db.relationship('Keys')
    keys_id = db.Column(db.Integer, db.ForeignKey('keys.id'))
    service = db.relationship('Service')
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'))
    approval = db.Column(db.Integer)
    comment = db.Column(db.String(2000))
    crl_cdp = db.Column(db.String(2000))
    ocsp_url = db.Column(db.String(2000))

    def __repr__(self):
        return '<Switch {}>'.format(self.name)

    def inventory_id(self):
        return '{}-{}'.format(self.__class__.__name__.lower(), self.id)

    def to_dict(self):
        data = {
            'id': self.id,
            'name': self.name,
            'certificate_id': self.certificate_id,
            'keys_id': self.keys_id,
            'service_id': self.service_id,
            'approval': self.approval,
            'validity_start': self.validity_start,
            'validity_end': self.validity_end,
            'cacert': self.certificate.cert,
            'crl_cdp': self.crl_cdp,
            'ocsp_url': self.ocsp_url,
            'comment': self.comment,
            }
        return data

    def from_dict(self, data):
        from app.main.models import Service

        for field in ['name', 'approval']:
            if field not in data:
                return {'msg': "must include field: %s" % field, 'success': False}
            else:
                setattr(self, field, data[field])

        # if 'keys_id' in data:
        #     keys = Keys.query.get(data['keys_id'])
        # elif 'keys_name' in data:
        #     keys = Keys.query.filter_by(name=data['keys_name']).first()
        #
        # if keys is None:
        #     return {'msg': "no service found via service_name nor id", 'success': False}
        # else:
        #     setattr(self, 'keys_id', keys.id)

        if 'service_id' in data:
            service = Service.query.get(data['service_id'])
        elif 'service_name' in data:
            service = Service.query.filter_by(name=data['service_name']).first()

        if service is None:
            return {'msg': "no service found via service_name nor id", 'success': False}
        else:
            setattr(self, 'service_id', service.id)

        return {'msg': "object loaded ok", 'success': True}

    def create_ca(self, certificate, passphrase):

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes

        # Generate our key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Write our key to disk for safe keeping
        keyfile = f"ca-{self.name}-key.pem"
        certfile = f"ca-{self.name}-cert.pem"

        with open(keyfile, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
            ))

        self.keys = Keys(key=key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase)),
                password=passphrase)

        # subject and issuer are always the same.
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"SE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TestCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
        ])

        cert = x509.CertificateBuilder().subject_name(subject)
        cert = cert.issuer_name(issuer)
        cert = cert.public_key(key.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(certificate.validity_start)
        cert = cert.not_valid_after(certificate.validity_end)
        cert = cert.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        )
        cert = cert.sign(key, hashes.SHA256())
        pemcert = cert.public_bytes(serialization.Encoding.PEM).decode()
        certificate.cert = pemcert
        self.certificate = certificate
        # Write our certificate out to disk.
        with open(certfile, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return cert

    def create_cert_from_csr(self, ca_passphrase, csr,
                             validity_start, validity_stop):

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        if csr.is_signature_valid is None:
            print(f'csr is not ok {csr}')

        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"SE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TestCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
        ])

        cert = x509.CertificateBuilder().subject_name(csr.subject)
        cert = cert.issuer_name(issuer)
        cert = cert.public_key(csr.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(validity_start)
        cert = cert.not_valid_after(validity_stop)

        # ca_pk = None
        # with open(ca_keyfile, "rb") as f:
        #     ca_pk = serialization.load_pem_private_key(
        #         f.read(), password=ca_passphrase)

        ca_pk = serialization.load_pem_private_key(
          self.keys.key, password=ca_passphrase)

        cert = cert.sign(ca_pk, hashes.SHA256())
        cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cns is None:
            # TODO: whaaat
            commonname = "foobar"
        else:
            commonname = cns[0].value

        objcert = Certificate(name=commonname,
                              status='active',
                              validity_start=validity_start,
                              validity_end=validity_stop
                              )
        objcert.ca = self
        pemcert = cert.public_bytes(serialization.Encoding.PEM).decode()
        txtcert = cert.public_bytes(serialization.Encoding.PEM).decode('UTF-8')
        txtcert = txtcert.replace('-----BEGIN CERTIFICATE-----', '')
        txtcert = txtcert.replace('-----END CERTIFICATE-----', '')
#        txtcert = txtcert.replace(' ', '\n')
        objcert.cert = pemcert
        db.session.add(objcert)
        db.session.commit()

        return objcert

    def create_cert(self, certificate, ca_passphrase, cert_passphrase, keys):

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import ExtendedKeyUsageOID, AuthorityInformationAccessOID

        temp_key = None
        if keys.key is None:
        # Generate our key
            temp_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                )
            keys.keys = temp_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(cert_passphrase))
        else:
            temp_key = serialization.load_pem_private_key(
                keys.key, password=keys.password)

# Write our key to disk for safe keeping
#        cert_keyfile = f"cert-{certificate.name}-key.pem"
#        cert_certfile = f"cert-{certificate.name}-cert.pem"
#        ca_keyfile = f"ca-{self.name}-key.pem"

        # with open(cert_keyfile, "wb") as f:
        #     f.write(temp_key.private_bytes(
        #         encoding=serialization.Encoding.PEM,
        #         format=serialization.PrivateFormat.TraditionalOpenSSL,
        #         encryption_algorithm=serialization.BestAvailableEncryption(cert_passphrase),
        #     ))

        subjectname_components = []
        if certificate.name is not None:
            subjectname_components.append(x509.NameAttribute(NameOID.COMMON_NAME, certificate.name))
        if certificate.userid is not None:
            subjectname_components.append(x509.NameAttribute(NameOID.USER_ID, certificate.userid))
        if certificate.serial is not None:
            subjectname_components.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, certificate.serial))
        if certificate.orgunit is not None:
            subjectname_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, certificate.orgunit))
        if certificate.org is not None:
            subjectname_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, certificate.org))
        if certificate.country is not None:
            subjectname_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, certificate.country))

        subject = x509.Name(subjectname_components)
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"SE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TestCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
        ])

        cert = x509.CertificateBuilder().subject_name(subject)
        cert = cert.issuer_name(issuer)
        cert = cert.public_key(temp_key.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(certificate.validity_start)
        cert = cert.not_valid_after(certificate.validity_end)
        if certificate.profile == "server" or certificate.profile == "server+client":

            sandnslist = []
            if certificate.sandns is not None:
                sanlist = certificate.sandns.split(",")
                for san in sanlist:
                    sandnslist.append(x509.DNSName(san))

            sandnslist.append(x509.DNSName(certificate.name))

            cert = cert.add_extension(x509.SubjectAlternativeName(sandnslist), critical=False)

        if certificate.profile == "server":
            cert = cert.add_extension(x509.ExtendedKeyUsage([
                                                ExtendedKeyUsageOID.SERVER_AUTH
                ]), critical=True)
            cert = cert.add_extension(x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ), critical=True)

        if certificate.profile == "client":
            cert = cert.add_extension(x509.ExtendedKeyUsage([
                                                ExtendedKeyUsageOID.CLIENT_AUTH
                ]), critical=True)
            cert = cert.add_extension(x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ), critical=True)

        if certificate.profile == "server+client":
            cert = cert.add_extension(x509.ExtendedKeyUsage([
                                                ExtendedKeyUsageOID.CLIENT_AUTH,
                                                ExtendedKeyUsageOID.SERVER_AUTH
                ]), critical=True)

            cert = cert.add_extension(x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ), critical=True)

        if certificate.profile == "digsig":

            cert = cert.add_extension(x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ), critical=True)

        if certificate.profile == "ocsp":
            cert = cert.add_extension(x509.ExtendedKeyUsage([
                                                ExtendedKeyUsageOID.OCSP_SIGNING
                ]), critical=True)

            cert = cert.add_extension(x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ), critical=True)

        if self.crl_cdp is not None:
            cert = cert.add_extension(x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(self.crl_cdp)
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None
                    )
                ]), critical=False)

        if self.ocsp_url is not None:
            cert = cert.add_extension(x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(self.ocsp_url)
                    )
                ]), critical=False)

        ca_pk = serialization.load_pem_private_key(
          self.keys.key, password=ca_passphrase)

        # add aki
        cert = cert.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_pk.public_key()), critical=False)
        # add ski
        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(
                temp_key.public_key()
            ), critical=False)

        cert = cert.sign(ca_pk, hashes.SHA256())
        certificate.cert_obj = cert
        # Write our certificate out to disk.
#        with open(cert_certfile, "wb") as f:
#            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return cert

    def create_crl(self, crl, passphrase):
        from cryptography.hazmat.primitives import serialization
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        import datetime

        builder = x509.CertificateRevocationListBuilder()
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"SE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TestCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
        ])
        builder = builder.issuer_name(issuer)
        builder = builder.last_update(crl.validity_start)
        builder = builder.next_update(crl.validity_end)
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            333
        ).revocation_date(
            datetime.datetime.today()

        ).build()
        builder = builder.add_revoked_certificate(revoked_cert)

        ca_pk = serialization.load_pem_private_key(
          self.keys.key, password=passphrase)

        crl = builder.sign(
            private_key=ca_pk, algorithm=hashes.SHA256(),
        )
        return crl
