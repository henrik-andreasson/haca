from flask import Blueprint

bp = Blueprint('crl', __name__)

from app.modules.crl import routes
