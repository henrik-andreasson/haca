from hashlib import md5
from time import time
from flask import current_app, g
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from app import db, login
from flask import url_for
import base64
from datetime import datetime, timedelta
import os
from sqlalchemy.ext.declarative import declarative_base
import uuid
from flask_login import current_user
from app.rocketchat import HACARocketChatClient


Base = declarative_base()

service_user = db.Table('service_user',
                        db.Column('service_id', db.Integer,
                                  db.ForeignKey('service.id')),
                        db.Column('user_id', db.Integer,
                                  db.ForeignKey('user.id'))
                        )


class PaginatedAPIMixin(object):
    @staticmethod
    def to_collection_dict(query, page, per_page, endpoint, **kwargs):
        resources = query.paginate(page, per_page, False)
        print("page: %s per_page: %s endpoint %s" % (page, per_page, endpoint))
        data = {
            'items': [item.to_dict() for item in resources.items],
            '_meta': {
                'page': page,
                'per_page': per_page,
                'total_pages': resources.pages,
                'total_items': resources.total
            },
            '_links': {
                'self': url_for(endpoint, id=id, page=page, per_page=per_page,
                                **kwargs),
                'next': url_for(endpoint, id=id, page=page + 1, per_page=per_page,
                                **kwargs) if resources.has_next else None,
                'prev': url_for(endpoint, id=id, page=page - 1, per_page=per_page,
                                **kwargs) if resources.has_prev else None
            }
        }
        return data


class Service(PaginatedAPIMixin, db.Model):
    __tablename__ = "service"
    __searchable__ = ['name']
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), unique=True)
    updated = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    color = db.Column(db.String(140))
    users = db.relationship('User', secondary=service_user)
    manager = db.relationship('User', foreign_keys='Service.manager_id')
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Service {}>'.format(self.name)

    def to_dict(self):
        data = {
            'id': self.id,
            'name': self.name,
            'color': self.color,
            'manager_id': self.manager_id
        }
        return data

    def from_dict(self, data, new_service=False):
        for field in ['name', 'color', 'manager_id']:
            if field in data:
                setattr(self, field, data[field])

    def inventory_id(self):
        return '{}-{}'.format(self.__class__.__name__.lower(), self.id)

    def get_users(self):
        data = {}
        for u in self.users:
            data[u.id] = u.username
        return data

    def set_users(self, data):
        for i in data:
            u = User.query.filter_by(id=i).first_or_404()
            self.users.append(u)
        return True


class User(PaginatedAPIMixin, UserMixin, db.Model):
    __tablename__ = "user"
    __searchable__ = ['username', 'email', 'about_me']
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    api_key = db.Column(db.String(32), index=True, unique=True)
    token = db.Column(db.String(32), index=True, unique=True)
    token_expiration = db.Column(db.DateTime)
    role = db.Column(db.String(140))
    active = db.Column(db.Integer)

#    service = db.relationship('Service')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            current_app.config['HACA_SECRET_KEY'],
            algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['HACA_SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

    def to_dict(self, include_email=False):
        data = {
            'id': self.id,
            'username': self.username,
            'last_seen': self.last_seen.isoformat() + 'Z',
            'about_me': self.about_me,
            '_links': {
                'self': url_for('api.get_user', id=self.id),
                'avatar': self.avatar(128)
            }
        }
        if include_email:
            data['email'] = self.email
        return data

    def from_dict(self, data, new_user=False):
        for field in ['username', 'email', 'about_me']:
            if field in data:
                setattr(self, field, data[field])
        if new_user and 'password' in data:
            self.set_password(data['password'])

    def get_token(self, expires_in=3600):
        now = datetime.utcnow()
        if self.token and self.token_expiration > now + timedelta(seconds=60):
            return self.token
        self.token = base64.b64encode(os.urandom(24)).decode('utf-8')
        self.token_expiration = now + timedelta(seconds=expires_in)
        db.session.add(self)
        return self.token

    def revoke_token(self):
        self.token_expiration = datetime.utcnow() - timedelta(seconds=1)

    @staticmethod
    def check_token(token):
        user = User.query.filter_by(token=token).first()
        if user is None or user.token_expiration < datetime.utcnow():
            return None
        return user

    def get_api_key(self):
        if self.api_key:
            return self.api_key
        self.api_key = str(uuid.uuid4())
        db.session.add(self)
        db.session.commit()
        return self.api_key

    def revoke_api_key(self):
        self.api_key = None
        db.session.add(self)
        db.session.commit()
        return self.api_key

    @staticmethod
    def check_api_key(user, api_key):
        if user is None or user.api_key is None:
            return False
        elif user.api_key == api_key:
            return True
        else:
            return False

    def inventory_id(self):
        return '{}-{}'.format(self.__class__.__name__.lower(), self.id)


@login.user_loader
def load_user(id):
    print(f'regular user loaded for login userid: {id}')
    return User.query.get(int(id))

#
# @login.request_loader
# def load_user_from_request(request):
#     s_dn = request.environ.get('HTTP_SSL_CLIENT_S_DN')
#
#     import pprint
#     pp = pprint.PrettyPrinter()
#     print("request dump >>>")
#     pp.pprint(request)
#     print("<<< end request dump")
#     if s_dn:
#         username_from_cert = dict([x.split('=') for x in s_dn.split(',')[1:]])[current_app.config['CERT_DN_COMP_IS_USERNAME']]
#         print(f'cert: {username_from_cert}')
#         user = User.query.filter_by(username=username_from_cert).first()
#         if user:
#             print(f'user {user.username} login via cert {s_dn}')
#             return user
#     else:
#         print('did not find cert info for login')
#
#     return None


class Audit(PaginatedAPIMixin, db.Model):
    __tablename__ = "audit"
    id = db.Column(db.Integer, primary_key=True)
    module = db.Column(db.String(140))
    record_name = db.Column(db.String(140))
    module_id = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    original_data = db.Column(db.Text)
    updated_data = db.Column(db.Text)
    updated_column = db.Column(db.String(255))
    user = db.relationship('User')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    type = db.Column(db.String(128))

    def __repr__(self):
        return '<Audit {}/{}/{}/{}>'.format(self.timestamp,
                                            self.module,
                                            self.original_data,
                                            self.updated_data)

    def record(self):
        return '{} - {} - {} - {}'.format(self.timestap, self.module,
                                          self.original_data, self.updated_data)

    def to_dict(self):
        data = {
            'id': self.id,
            'module': self.module,
            'module_id': self.module_id,
            'timestamp': self.timestamp,
            'original_data': self.original_data,
            'updated_data': self.updated_data,
            'updated_column': self.updated_column,
            'type': self.type,
            'user_id': self.user_id
        }
        return data

    def from_dict(self, data):
        for field in ['id', 'module', 'module_id', 'timestamp', 'original_data',
                      'updated_data', 'type', 'user_id']:
            if field in data:
                setattr(self, field, data[field])

    def dict_to_string(self, dict):
        str = ""
        for field in dict.keys():
            str += "{}: {} ".format(field, dict[field])
        return str

    def auditlog_new_post(self, module, original_data, record_name):
        ts = datetime.utcnow()
        if hasattr(g, 'current_user'):
            user = User.query.filter_by(
                username=g.current_user.username).first()
        else:
            user = User.query.filter_by(username=current_user.username).first()
        audit = Audit(module=module, module_id=original_data['id'],
                      timestamp=ts, record_name=record_name,
                      original_data=self.dict_to_string(original_data),
                      type='new', user=user)
        db.session.add(audit)
        db.session.commit()
        rocket = HACARocketChatClient()
        rs = "{} added {} a {} with data {}".format(
            user.username, record_name, module, self.dict_to_string(original_data))
        rocket.send_message_to_rocket_chat(rs)

    def auditlog_update_post(self, module, original_data, updated_data, record_name):
        ts = datetime.utcnow()
        if hasattr(g, 'current_user'):
            user = User.query.filter_by(
                username=g.current_user.username).first()
        else:
            user = User.query.filter_by(username=current_user.username).first()

        for field in updated_data:
            if original_data[field] != updated_data[field]:
                audit = Audit(module=module, module_id=original_data['id'],
                              timestamp=ts, record_name=record_name,
                              original_data=original_data[field],
                              updated_data=updated_data[field],
                              updated_column=field,
                              type='update', user=user)
                db.session.add(audit)
                db.session.commit()
                rocket = HACARocketChatClient()
                rs = "{} changed {} a {} field: {} from: {} to: {}".format(
                    user.username, record_name, module, field, original_data[field], updated_data[field])
                rocket.send_message_to_rocket_chat(rs)

    def auditlog_delete_post(self, module, data, record_name):
        ts = datetime.utcnow()
        if hasattr(g, 'current_user'):
            user = User.query.filter_by(
                username=g.current_user.username).first()
        else:
            user = User.query.filter_by(username=current_user.username).first()

        audit = Audit(module=module, module_id=self.id, timestamp=ts,
                      original_data=self.dict_to_string(data),
                      record_name=record_name,
                      type='delete', user=user)
        db.session.add(audit)
        db.session.commit()

    def inventory_id(self):
        return '{}-{}'.format(self.__class__.__name__.lower(), self.id)


def log(json_log):
    # log_row = {
    #     'cert name': certobj.subject.rfc4514_string(),
    #     'cert serial': certobj.serial_number,
    #     'issuer name': issuer.subject.rfc4514_string(),
    #     'status': str(ocspstatus),
    #     'delta_t (ms)': delta_t_ms_str
    #     }
    from json import dumps
    print(dumps(json_log))

    if 'title' in json_log:
        print(f'{json_log["title"]}')
        del json_log['title']
    for key in json_log.keys():
        print(f'   {key}: {json_log[key]}')
