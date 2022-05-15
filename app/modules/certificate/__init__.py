from flask import Blueprint

bp = Blueprint('cert', __name__)

from app.modules.certificate import routes
