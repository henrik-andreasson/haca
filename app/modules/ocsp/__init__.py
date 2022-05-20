from flask import Blueprint

bp = Blueprint('ocsp', __name__)

from app.modules.ocsp import routes
