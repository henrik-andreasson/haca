from app import create_app, db, cli
from app.main.models import User, Service

app = create_app()
cli.register(app)


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Service': Service}
