from flask import Blueprint

bp = Blueprint('ca', __name__)

from app.modules.ca import routes
