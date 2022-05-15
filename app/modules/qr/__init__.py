from flask import Blueprint

bp = Blueprint('qr', __name__)

from app.modules.qr import routes
