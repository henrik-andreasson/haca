from flask import Blueprint

bp = Blueprint('api', __name__)

from app.api import users, errors, tokens, certificate, crl, ca, ocsp

# todo, service
