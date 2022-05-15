from flask import Blueprint

bp = Blueprint('safe', __name__)

from app.modules.safe import routes
