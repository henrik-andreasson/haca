import os
import logging

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    SECRET_KEY = os.environ.get('INVENTORPY_SECRET_KEY') or 'you-will-never-guess'
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME') or 'http'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'ca.db')
#    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
#        'mysql+pymysql://haca:foo123@172.21.0.2/haca'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = ['your-email@example.com']
    POSTS_PER_PAGE = 25
    LANGUAGES = ['en', 'es']
    ROCKET_ENABLED = os.environ.get('ROCKET_ENABLED') or False
    ROCKET_USER = os.environ.get('ROCKET_USER') or 'inventory'
    ROCKET_PASS = os.environ.get('ROCKET_PASS') or 'foo123'
    ROCKET_URL = os.environ.get('ROCKET_URL') or 'http://172.17.0.4:3000'
    ROCKET_CHANNEL = os.environ.get('ROCKET_CHANNEL') or 'general'
    OPEN_REGISTRATION = os.environ.get('OPEN_REGISTRATION') or True
    INVENTORPY_TZ = os.environ.get('TEAMPLAN_TZ') or "Europe/Stockholm"
    CERT_LOGIN = os.environ.get('CERT_LOGIN') or False
    CERT_DN_COMP_IS_USERNAME = os.environ.get('CERT_DN_COMP_IS_USERNAME') or "CN"
    PROXY_FIX = os.environ.get('PROXY_FIX') or 0

    # flask-msearch will use table name as elasticsearch index name unless set __msearch_index__
    MSEARCH_INDEX_NAME = 'msearch'
    # simple,whoosh,elaticsearch, default is simple
    MSEARCH_BACKEND = 'whoosh'
    # table's primary key if you don't like to use id, or set __msearch_primary_key__ for special model
    MSEARCH_PRIMARY_KEY = 'id'
    # auto create or update index
    MSEARCH_ENABLE = True
    # logger level, default is logging.WARNING
    MSEARCH_LOGGER = logging.DEBUG
    # SQLALCHEMY_TRACK_MODIFICATIONS must be set to True when msearch auto index is enabled
    SQLALCHEMY_TRACK_MODIFICATIONS = True
