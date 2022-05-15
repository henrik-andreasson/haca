from flask import render_template, flash, redirect, url_for, request, g, current_app
from flask_login import current_user, login_required
from flask_babel import _, get_locale
from app import db
from app.main.forms import EditProfileForm, ServiceForm, SearchForm
from app.main.models import User, Service, Audit
from app.modules.certificate.models import Certificate
# from app.modules.approval.models import Approval
from app.main import bp
from datetime import datetime


@bp.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
    g.locale = str(get_locale())


@bp.route('/', methods=['GET', 'POST'])
@login_required
def index():

    users = User.query.order_by(User.username).limit(10)
    services = Service.query.order_by(Service.name).limit(10)
    certificates = Certificate.query.order_by(Certificate.name).limit(10)

    return render_template('index.html', title=_('Explore'),
                           services=services, users=users,
                           certificates=certificates)


@bp.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    keyword = request.args.get('keyword')
    form = SearchForm()
    if keyword is None:
        if 'keyword' in request.form:
            keyword = form.keyword.data

    users = []
    hits = []
    if keyword is not None:
        users = User.query.msearch(keyword, rank_order=False).all()
        for u in users:
            hit = {'title': u.username, 'module': 'User', 'text': u.about_me,
                   'link': url_for('main.user', username=u.username)}
            hits.append(hit)

        services = Service.query.msearch(keyword, rank_order=False).all()
        for s in services:
            hit = {'title': s.name, 'module': 'Service', 'text': s.name,
                   'link': url_for('main.service_get', servicename=s.name)}
            hits.append(hit)

        certificates = Certificate.query.msearch(keyword, rank_order=False).all()
        for c in certificates:
            hit = {'title': f'{c.name}',
                   'module': 'Certificate', 'text': f'{c.name} - {c.name} - {c.name}',
                   'link': url_for('main.certificate_view', id=c.id)}
            hits.append(hit)

# Switch
    return render_template('search.html', title=_('Search'),
                           hits=hits, form=form)


@bp.route('/reindex', methods=['GET', 'POST'])
@login_required
def reindex():
    from app import search
    search.delete_index()
    search.create_index()

    return render_template('search.html', reindex=_("Reindexed"))


@bp.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    print("user: %s" % (user.username))
    services = Service.query.all()

    return render_template('user.html', user=user,
                           services=services, title=_("User"))


@bp.route('/user/list')
@login_required
def user_list():
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.username).paginate(
        page, current_app.config['POSTS_PER_PAGE'], False)
    services = Service.query.all()

    next_url = url_for(
        'main.user_list', page=users.next_num) if users.has_next else None
    prev_url = url_for(
        'main.user_list', page=users.prev_num) if users.has_prev else None
    return render_template('users.html', users=users.items, services=services,
                           next_url=next_url, prev_url=prev_url,
                           title=_("User List"))


@bp.route('/service/add', methods=['GET', 'POST'])
@login_required
def service_add():
    if 'cancel' in request.form:
        return redirect(request.referrer)

    form = ServiceForm()

    if form.validate_on_submit():
        service = Service(name=form.name.data, color=form.color.data)
        for u in form.users.data:
            user = User.query.filter_by(id=u).first()
            print("Adding: User: %s to: %s" % (user.username, service.name))
            service.users.append(user)
        service.manager = User.query.filter_by(id=form.manager.data).first()

        db.session.add(service)
        db.session.commit()
        #  audit.auditlog_new_post(
        #    'service', original_data=service.to_dict(), record_name=service.name)
        flash(_('Service have been saved.'))
        return redirect(url_for('main.service_list'))

    else:
        return render_template('service.html', form=form,
                               title=_("Add Service"))


@bp.route('/service/edit', methods=['GET', 'POST'])
@login_required
def service_edit():
    if 'cancel' in request.form:
        return redirect(request.referrer)

    servicename = request.args.get('name')
    service = Service.query.filter_by(name=servicename).first()
    # original_data = service.to_dict()
    if service is None:
        render_template('service.html', title=_('Service is not defined'))

    form = ServiceForm(formdata=request.form, obj=service)

    if request.method == 'POST' and form.validate_on_submit():
        # TODO remove not selected users ...
        service.users = []
        for u in form.users.data:
            user = User.query.filter_by(id=u).first()
            print("Adding: User: %s to: %s" % (user.username, service.name))
            service.users.append(user)
        service.manager = User.query.filter_by(id=form.manager.data).first()
        service.name = form.name.data
        service.color = form.color.data

        db.session.commit()
        #  audit.auditlog_update_post('service', original_data=original_data,
        #                           updated_data=service.to_dict(), record_name=service.name)

        flash(_('Your changes have been saved.'))
        return redirect(url_for('main.service_list'))

    else:

        pre_selected_users = [(su.id) for su in service.users]
        form = ServiceForm(users=pre_selected_users)
        form.manager.data = service.manager_id
        form.name.data = service.name
        form.color.data = service.color
        return render_template('service.html', title=_('Edit Service'),
                               form=form)


@bp.route('/service/list/', methods=['GET', 'POST'])
@login_required
def service_list():
    page = request.args.get('page', 1, type=int)
    services = Service.query.order_by(Service.updated.desc()).paginate(
        page, current_app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('main.service_list',
                       page=services.next_num) if services.has_next else None
    prev_url = url_for('main.service_list',
                       page=services.prev_num) if services.has_prev else None
    return render_template('services.html', services=services.items,
                           next_url=next_url, prev_url=prev_url,
                           title=_("List Service"))


@bp.route('/service/<servicename>', methods=['GET'])
@login_required
def service_get(servicename):
    service = Service.query.filter_by(name=servicename).first_or_404()
    print("service: %s" % (service.name))

    return render_template('service.html', service=service, title=_('Service'))


@bp.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
# todo audit + rewrite
        flash(_('Your changes have been saved.'))
        return redirect(url_for('main.edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title=_('Edit Profile'),
                           form=form)
#
#
# @bp.route('/updates/list/', methods=['GET'])
# @login_required
# def updates_list():
#     page = request.args.get('page', 1, type=int)
#     approvals = Approval.query.order_by(Approval.id).paginate(
#         page, current_app.config['POSTS_PER_PAGE'], False)
#     next_url = url_for(
#         'main.updates_list', page=approvals.next_num) if approvals.has_next else None
#     prev_url = url_for(
#         'main.updates_list', page=approvals.prev_num) if approvals.has_prev else None
#     return render_template('approval.html', approval=approvals.items,
#                            next_url=next_url, prev_url=prev_url,
#                            title=_('HSM Update'))


@bp.route('/logs/list/', methods=['GET', 'POST'])
@login_required
def logs_list():
    page = request.args.get('page', 1, type=int)
    module = request.args.get('module')
    module_id = request.args.get('module_id', type=int)
    logs_for_user = request.args.get('user_id', type=int)

    if logs_for_user is not None:
        logs = Audit.query.filter_by(user_id=logs_for_user).paginate(
            page, current_app.config['POSTS_PER_PAGE'], False)
    elif module is not None and module_id is not None:
        logs = Audit.query.filter_by(module=module, module_id=module_id).paginate(
            page, current_app.config['POSTS_PER_PAGE'], False)
    elif module is not None:
        logs = Audit.query.filter_by(module=module).paginate(
            page, current_app.config['POSTS_PER_PAGE'], False)
    else:
        logs = Audit.query.order_by(Audit.timestamp.desc()).paginate(
            page, current_app.config['POSTS_PER_PAGE'], False)

    next_url = url_for(
        'main.logs_list', page=logs.next_num) if logs.has_next else None
    prev_url = url_for(
        'main.logs_list', page=logs.prev_num) if logs.has_prev else None
    return render_template('logs.html', logs=logs.items,
                           next_url=next_url, prev_url=prev_url,
                           title=_('Logs'))
