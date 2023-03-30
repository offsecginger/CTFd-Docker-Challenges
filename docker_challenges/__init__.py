import traceback

from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES
from CTFd.plugins.flags import get_flag_class
from CTFd.utils.user import get_ip
from CTFd.utils.uploads import delete_file
from CTFd.plugins import register_plugin_assets_directory
from CTFd.models import db, Challenges, Teams, Users, Solves, Fails, Flags, Hints, Tags, ChallengeFiles
from CTFd.utils.decorators import admins_only, authed_only
from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.config import is_teams_mode
from CTFd.api import CTFd_API_v1
from flask_restx import Namespace, Resource
from flask import request, Blueprint, abort, render_template, session
from wtforms import (
    FileField,
    HiddenField,
    IntegerField,
    RadioField,
    StringField,
    SelectMultipleField,
)
import requests
import tempfile
from CTFd.utils.dates import unix_time
from datetime import datetime
import json
import hashlib
import random

from CTFd.forms import BaseForm
from CTFd.forms.fields import SubmitField


class DockerConfig(db.Model):
    """
	Docker Config Model. This model stores the config for docker API connections.
	"""
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column("hostname", db.String(64), index=True)
    tls_enabled = db.Column("tls_enabled", db.Boolean, default=False, index=True)
    ca_cert = db.Column("ca_cert", db.String(2200), index=True)
    client_cert = db.Column("client_cert", db.String(2000), index=True)
    client_key = db.Column("client_key", db.String(3300), index=True)
    memory_limit = db.Column("memory_limit", db.BigInteger)
    cpu_period = db.Column("cpu_period", db.BigInteger)
    cpu_quota = db.Column("cpu_quota", db.BigInteger)
    repositories = db.Column("repositories", db.String(1024), index=True)


class DockerChallengeTracker(db.Model):
    """
	Docker Container Tracker. This model stores the users/teams active docker containers.
	"""
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column("team_id", db.String(64), index=True)
    user_id = db.Column("user_id", db.String(64), index=True)
    docker_image = db.Column("docker_image", db.String(64), index=True)
    timestamp = db.Column("timestamp", db.Integer, index=True)
    revert_time = db.Column("revert_time", db.Integer, index=True)
    instance_id = db.Column("instance_id", db.String(128), index=True)
    ports = db.Column('ports', db.String(128), index=True)
    host = db.Column('host', db.String(128), index=True)


class DockerConfigForm(BaseForm):
    id = HiddenField()
    hostname = StringField(
        "Docker Hostname", description="The Hostname/IP and Port of your Docker Server"
    )
    tls_enabled = RadioField('TLS Enabled?')
    ca_cert = FileField('CA Cert')
    client_cert = FileField('Client Cert')
    client_key = FileField('Client Key')
    memory_limit = IntegerField('Memory Limit per Container (Bytes)')
    cpu_period = IntegerField('CPU Period per Container (Microseconds)')
    cpu_quota = IntegerField('CPU Quota per Container (Microseconds)')
    repositories = SelectMultipleField('Repositories')
    submit = SubmitField('Submit')


def define_docker_admin(app):
    admin_docker_config = Blueprint('admin_docker_config', __name__, template_folder='templates',
                                    static_folder='assets')

    @admin_docker_config.route("/admin/docker_config", methods=["GET", "POST"])
    @admins_only
    def docker_config():
        docker = DockerConfig.query.filter_by(id=1).first()
        form = DockerConfigForm()
        if request.method == "POST":
            if docker:
                b = docker
            else:
                b = DockerConfig()
            try:
                ca_cert = request.files['ca_cert'].stream.read()
            except:
                print(traceback.print_exc())
                ca_cert = ''
            try:
                client_cert = request.files['client_cert'].stream.read()
            except:
                print(traceback.print_exc())
                client_cert = ''
            try:
                client_key = request.files['client_key'].stream.read()
            except:
                print(traceback.print_exc())
                client_key = ''
            if len(ca_cert) != 0: b.ca_cert = ca_cert
            if len(client_cert) != 0: b.client_cert = client_cert
            if len(client_key) != 0: b.client_key = client_key
            b.hostname = request.form['hostname']
            b.tls_enabled = request.form['tls_enabled']
            if b.tls_enabled == "True":
                b.tls_enabled = True
            else:
                b.tls_enabled = False
            if not b.tls_enabled:
                b.ca_cert = None
                b.client_cert = None
                b.client_key = None
            b.memory_limit = None if request.form['memory_limit'] in [None, ''] else request.form['memory_limit']
            b.cpu_period = None if request.form['cpu_period'] in [None, ''] else request.form['cpu_period']
            b.cpu_quota = None if request.form['cpu_quota'] in [None, ''] else request.form['cpu_quota']
            try:
                b.repositories = ','.join(request.form.to_dict(flat=False)['repositories'])
            except:
                print(traceback.print_exc())
                b.repositories = None
            db.session.add(b)
            db.session.commit()
            docker = DockerConfig.query.filter_by(id=1).first()
        try:
            repos = get_repositories(docker)
        except:
            print(traceback.print_exc())
            repos = list()
        if len(repos) == 0:
            form.repositories.choices = [("ERROR", "Failed to Connect to Docker")]
        else:
            form.repositories.choices = [(d, d) for d in repos]
        dconfig = DockerConfig.query.first()
        try:
            selected_repos = dconfig.repositories
            if selected_repos == None:
                selected_repos = list()
        # selected_repos = dconfig.repositories.split(',')
        except:
            print(traceback.print_exc())
            selected_repos = []
        return render_template("docker_config.html", config=dconfig, form=form, repos=selected_repos)

    app.register_blueprint(admin_docker_config)


def define_docker_status(app):
    admin_docker_status = Blueprint('admin_docker_status', __name__, template_folder='templates',
                                    static_folder='assets')

    @admin_docker_status.route("/admin/docker_status", methods=["GET", "POST"])
    @admins_only
    def docker_admin():
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        for i in docker_tracker:
            if is_teams_mode():
                name = Teams.query.filter_by(id=i.team_id).first()
                i.team_id = name.name
            else:
                name = Users.query.filter_by(id=i.user_id).first()
                i.user_id = name.name
        return render_template("admin_docker_status.html", dockers=docker_tracker)

    app.register_blueprint(admin_docker_status)


kill_container = Namespace("nuke", description='Endpoint to nuke containers')


@kill_container.route("", methods=['POST', 'GET'])
class KillContainerAPI(Resource):
    @admins_only
    def get(self):
        container = request.args.get('container')
        full = request.args.get('all')
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        if full == "true":
            for c in docker_tracker:
                delete_container(docker_config, c.instance_id)
                DockerChallengeTracker.query.filter_by(instance_id=c.instance_id).delete()
                db.session.commit()

        elif container != 'null' and container in [c.instance_id for c in docker_tracker]:
            delete_container(docker_config, container)
            DockerChallengeTracker.query.filter_by(instance_id=container).delete()
            db.session.commit()

        else:
            return False
        return True


def do_request(docker, url, headers=None, method='GET'):
    tls = docker.tls_enabled
    prefix = 'https' if tls else 'http'
    host = docker.hostname
    URL_TEMPLATE = '%s://%s' % (prefix, host)
    try:
        if tls:
            cert = get_client_cert(docker)
            if (method == 'GET'):
                r = requests.get(url=f"%s{url}" % URL_TEMPLATE, cert=cert[0:2], verify=cert[2], headers=headers)
            elif (method == 'DELETE'):
                r = requests.delete(url=f"%s{url}" % URL_TEMPLATE, cert=cert[0:2], verify=cert[2], headers=headers)
        else:
            if (method == 'GET'):
                r = requests.get(url=f"%s{url}" % URL_TEMPLATE, headers=headers)
            elif (method == 'DELETE'):
                r = requests.delete(url=f"%s{url}" % URL_TEMPLATE, headers=headers)
    except:
        print(traceback.print_exc())
        r = []
    return r


def get_client_cert(docker):
    try:
        ca = docker.ca_cert
        client = docker.client_cert
        ckey = docker.client_key
        ca_file = tempfile.NamedTemporaryFile(delete=False)
        ca_file.write(ca.encode('utf-8'))
        ca_file.seek(0)
        client_file = tempfile.NamedTemporaryFile(delete=False)
        client_file.write(client.encode('utf-8'))
        client_file.seek(0)
        key_file = tempfile.NamedTemporaryFile(delete=False)
        key_file.write(ckey.encode('utf-8'))
        key_file.seek(0)
        CERT = (client_file.name, key_file.name, ca_file.name)
    except:
        print(traceback.print_exc())
        CERT = None
    return CERT


# For the Docker Config Page. Gets the Current Repositories available on the Docker Server.
def get_repositories(docker, tags=False, repos=False):
    r = do_request(docker, '/images/json?all=1')
    result = list()
    for i in r.json():
        if not i['RepoTags'] == None:
            if not i['RepoTags'][0].split(':')[0] == '<none>':
                if repos:
                    if not i['RepoTags'][0].split(':')[0] in repos:
                        continue
                if not tags:
                    result.append(i['RepoTags'][0].split(':')[0])
                else:
                    result.append(i['RepoTags'][0])
    return list(set(result))


def get_unavailable_ports(docker):
    r = do_request(docker, '/containers/json?all=1')
    result = list()
    for i in r.json():
        if not i['Ports'] == []:
            for p in i['Ports']:
                if 'PublicPort'in p:
                    result.append(p['PublicPort'])
    return result


def get_required_ports(docker, image):
    r = do_request(docker, f'/images/{image}/json?all=1')
    result = r.json()
    ports = (result['ContainerConfig']['ExposedPorts']\
        if 'ExposedPorts' in result['ContainerConfig']\
        else result['Config']['ExposedPorts']).keys()
    return ports


def create_container(docker, image, team, portbl):
    tls = docker.tls_enabled
    CERT = None
    prefix = 'https' if tls else 'http'
    URL_TEMPLATE = '%s://%s' % (prefix, docker.hostname)
    challenge = DockerChallenge.query.filter_by(docker_image=image).first()
    needed_ports = challenge.ports.split(',') if challenge.ports else get_required_ports(docker, image)
    team = hashlib.md5(team.encode("utf-8")).hexdigest()[:10]
    container_name = "%s_%s" % (image.split(':')[1], team)
    assigned_ports = dict()
    for i in needed_ports:
        while True:
            assigned_port = random.choice(range(30000, 60000))
            if assigned_port not in portbl:
                assigned_ports['%s/tcp' % assigned_port] = {}
                break
    ports = dict()
    bindings = dict()
    tmp_ports = list(assigned_ports.keys())
    for i in needed_ports:
        ports[i] = {}
        bindings[i] = [{"HostPort": tmp_ports.pop()}]
    headers = {'Content-Type': "application/json"}
    params = {"Image": image, "ExposedPorts": ports, "HostConfig": {"PortBindings": bindings}}
    if docker.memory_limit:
        params["HostConfig"]["Memory"] = docker.memory_limit
    if docker.cpu_period:
        params["HostConfig"]["CpuPeriod"] = docker.cpu_period
    if docker.cpu_quota:
        params["HostConfig"]["CpuQuota"] = docker.cpu_quota
    data = json.dumps(params)
    if tls:
        cert = get_client_cert(docker)
        r = requests.post(url="%s/containers/create?name=%s" % (URL_TEMPLATE, container_name), cert=cert[0:2],
                      verify=cert[2], data=data, headers=headers)
        result = r.json()
        s = requests.post(url="%s/containers/%s/start" % (URL_TEMPLATE, result['Id']), cert=cert[0:2], verify=cert[2],
                          headers=headers)
    else:
        r = requests.post(url="%s/containers/create?name=%s" % (URL_TEMPLATE, container_name),
                          data=data, headers=headers)
        print(r.request.method, r.request.url, r.request.body)
        result = r.json()
        print(result)
        # name conflicts are not handled properly
        s = requests.post(url="%s/containers/%s/start" % (URL_TEMPLATE, result['Id']), headers=headers)
    return result, data


def delete_container(docker, instance_id):
    headers = {'Content-Type': "application/json"}
    do_request(docker, f'/containers/{instance_id}?force=true', headers=headers, method='DELETE')
    return True


class DockerChallengeType(BaseChallenge):
    id = "docker"
    name = "docker"
    templates = {
        'create': '/plugins/docker_challenges/assets/create.html',
        'update': '/plugins/docker_challenges/assets/update.html',
        'view': '/plugins/docker_challenges/assets/view.html',
    }
    scripts = {
        'create': '/plugins/docker_challenges/assets/create.js',
        'update': '/plugins/docker_challenges/assets/update.js',
        'view': '/plugins/docker_challenges/assets/view.js',
    }
    route = '/plugins/docker_challenges/assets'
    blueprint = Blueprint('docker_challenges', __name__, template_folder='templates', static_folder='assets')

    @staticmethod
    def update(challenge, request):
        """
		This method is used to update the information associated with a challenge. This should be kept strictly to the
		Challenges table and any child tables.

		:param challenge:
		:param request:
		:return:
		"""
        data = request.form or request.get_json()
        for attr, value in data.items():
            setattr(challenge, attr, value)

        db.session.commit()
        return challenge

    @staticmethod
    def delete(challenge):
        """
		This method is used to delete the resources used by a challenge.
		NOTE: Will need to kill all containers here

		:param challenge:
		:return:
		"""
        Fails.query.filter_by(challenge_id=challenge.id).delete()
        Solves.query.filter_by(challenge_id=challenge.id).delete()
        Flags.query.filter_by(challenge_id=challenge.id).delete()
        files = ChallengeFiles.query.filter_by(challenge_id=challenge.id).all()
        for f in files:
            delete_file(f.id)
        ChallengeFiles.query.filter_by(challenge_id=challenge.id).delete()
        Tags.query.filter_by(challenge_id=challenge.id).delete()
        Hints.query.filter_by(challenge_id=challenge.id).delete()
        DockerChallenge.query.filter_by(id=challenge.id).delete()
        Challenges.query.filter_by(id=challenge.id).delete()
        db.session.commit()

    @staticmethod
    def read(challenge):
        """
		This method is in used to access the data of a challenge in a format processable by the front end.

		:param challenge:
		:return: Challenge object, data dictionary to be returned to the user
		"""
        challenge = DockerChallenge.query.filter_by(id=challenge.id).first()
        data = {
            'id': challenge.id,
            'name': challenge.name,
            'value': challenge.value,
            'docker_image': challenge.docker_image,
            'ports': challenge.ports,
            'description': challenge.description,
            'category': challenge.category,
            'state': challenge.state,
            'max_attempts': challenge.max_attempts,
            'type': challenge.type,
            'type_data': {
                'id': DockerChallengeType.id,
                'name': DockerChallengeType.name,
                'templates': DockerChallengeType.templates,
                'scripts': DockerChallengeType.scripts,
            }
        }
        return data

    @staticmethod
    def create(request):
        """
		This method is used to process the challenge creation request.

		:param request:
		:return:
		"""
        data = request.form or request.get_json()
        challenge = DockerChallenge(**data)
        db.session.add(challenge)
        db.session.commit()
        return challenge

    @staticmethod
    def attempt(challenge, request):
        """
		This method is used to check whether a given input is right or wrong. It does not make any changes and should
		return a boolean for correctness and a string to be shown to the user. It is also in charge of parsing the
		user's input from the request itself.

		:param challenge: The Challenge object from the database
		:param request: The request the user submitted
		:return: (boolean, string)
		"""

        data = request.form or request.get_json()
        print(request.get_json())
        print(data)
        submission = data["submission"].strip()
        flags = Flags.query.filter_by(challenge_id=challenge.id).all()
        for flag in flags:
            if get_flag_class(flag.type).compare(flag, submission):
                return True, "Correct"
        return False, "Incorrect"

    @staticmethod
    def solve(user, team, challenge, request):
        """
		This method is used to insert Solves into the database in order to mark a challenge as solved.

		:param team: The Team object from the database
		:param chal: The Challenge object from the database
		:param request: The request the user submitted
		:return:
		"""
        data = request.form or request.get_json()
        submission = data["submission"].strip()
        docker = DockerConfig.query.filter_by(id=1).first()
        try:
            if is_teams_mode():
                docker_containers = DockerChallengeTracker.query.filter_by(
                    docker_image=challenge.docker_image).filter_by(team_id=team.id).first()
            else:
                docker_containers = DockerChallengeTracker.query.filter_by(
                    docker_image=challenge.docker_image).filter_by(user_id=user.id).first()
            delete_container(docker, docker_containers.instance_id)
            DockerChallengeTracker.query.filter_by(instance_id=docker_containers.instance_id).delete()
        except:
            pass
        solve = Solves(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(req=request),
            provided=submission,
        )
        db.session.add(solve)
        db.session.commit()
        # trying if this solces the detached instance error...
        #db.session.close()

    @staticmethod
    def fail(user, team, challenge, request):
        """
		This method is used to insert Fails into the database in order to mark an answer incorrect.

		:param team: The Team object from the database
		:param chal: The Challenge object from the database
		:param request: The request the user submitted
		:return:
		"""
        data = request.form or request.get_json()
        submission = data["submission"].strip()
        wrong = Fails(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(request),
            provided=submission,
        )
        db.session.add(wrong)
        db.session.commit()
        #db.session.close()


class DockerChallenge(Challenges):
    __mapper_args__ = {'polymorphic_identity': 'docker'}
    id = db.Column(None, db.ForeignKey('challenges.id'), primary_key=True)
    docker_image = db.Column(db.String(128), index=True)
    ports = db.Column(db.String(128), nullable=True)


# API
container_namespace = Namespace("container", description='Endpoint to interact with containers')


@container_namespace.route("", methods=['POST', 'GET'])
class ContainerAPI(Resource):
    @authed_only
    # I wish this was Post... Issues with API/CSRF and whatnot. Open to a Issue solving this.
    def get(self):
        container = request.args.get('name')
        if not container:
            return abort(403)
        docker = DockerConfig.query.filter_by(id=1).first()
        containers = DockerChallengeTracker.query.all()
        if container not in get_repositories(docker, tags=True):
            return abort(403)
        if is_teams_mode():
            session = get_current_team()
            # First we'll delete all old docker containers (+2 hours)
            for i in containers:
                if int(session.id) == int(i.team_id) and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200:
                    delete_container(docker, i.instance_id)
                    DockerChallengeTracker.query.filter_by(instance_id=i.instance_id).delete()
                    db.session.commit()
            check = DockerChallengeTracker.query.filter_by(team_id=session.id).filter_by(docker_image=container).first()
        else:
            session = get_current_user()
            for i in containers:
                if int(session.id) == int(i.user_id) and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200:
                    delete_container(docker, i.instance_id)
                    DockerChallengeTracker.query.filter_by(instance_id=i.instance_id).delete()
                    db.session.commit()
            check = DockerChallengeTracker.query.filter_by(user_id=session.id).filter_by(docker_image=container).first()
        # If this container is already created, we don't need another one.
        if check != None and not (unix_time(datetime.utcnow()) - int(check.timestamp)) >= 300:
            return abort(403)
        # The exception would be if we are reverting a box. So we'll delete it if it exists and has been around for more than 5 minutes.
        elif check != None:
            delete_container(docker, check.instance_id)
            if is_teams_mode():
                DockerChallengeTracker.query.filter_by(team_id=session.id).filter_by(docker_image=container).delete()
            else:
                DockerChallengeTracker.query.filter_by(user_id=session.id).filter_by(docker_image=container).delete()
            db.session.commit()
        portsbl = get_unavailable_ports(docker)
        create = create_container(docker, container, session.name, portsbl)
        ports = json.loads(create[1])['HostConfig']['PortBindings'].values()
        entry = DockerChallengeTracker(
            team_id=session.id if is_teams_mode() else None,
            user_id=session.id if not is_teams_mode() else None,
            docker_image=container,
            timestamp=unix_time(datetime.utcnow()),
            revert_time=unix_time(datetime.utcnow()) + 300,
            instance_id=create[0]['Id'],
            ports=','.join([p[0]['HostPort'] for p in ports]),
            host=str(docker.hostname).split(':')[0]
        )
        db.session.add(entry)
        db.session.commit()
        #db.session.close()
        return


active_docker_namespace = Namespace("docker", description='Endpoint to retrieve User Docker Image Status')


@active_docker_namespace.route("", methods=['POST', 'GET'])
class DockerStatus(Resource):
    """
	The Purpose of this API is to retrieve a public JSON string of all docker containers
	in use by the current team/user.
	"""

    @authed_only
    def get(self):
        docker = DockerConfig.query.filter_by(id=1).first()
        if is_teams_mode():
            session = get_current_team()
            tracker = DockerChallengeTracker.query.filter_by(team_id=session.id)
        else:
            session = get_current_user()
            tracker = DockerChallengeTracker.query.filter_by(user_id=session.id)
        data = list()
        for i in tracker:
            data.append({
                'id': i.id,
                'team_id': i.team_id,
                'user_id': i.user_id,
                'docker_image': i.docker_image,
                'timestamp': i.timestamp,
                'revert_time': i.revert_time,
                'instance_id': i.instance_id,
                'ports': i.ports.split(','),
                'host': str(docker.hostname).split(':')[0]
            })
        return {
            'success': True,
            'data': data
        }


docker_namespace = Namespace("docker", description='Endpoint to retrieve dockerstuff')


@docker_namespace.route("", methods=['POST', 'GET'])
class DockerAPI(Resource):
    """
	This is for creating Docker Challenges. The purpose of this API is to populate the Docker Image Select form
	object in the Challenge Creation Screen.
	"""

    @admins_only
    def get(self):
        docker = DockerConfig.query.filter_by(id=1).first()
        images = get_repositories(docker, tags=True, repos=docker.repositories)
        if images:
            data = list()
            for i in images:
                data.append({'name': i})
            return {
                'success': True,
                'data': data
            }
        else:
            return {
                       'success': False,
                       'data': [
                           {
                               'name': 'Error in Docker Config!'
                           }
                       ]
                   }, 400


docker_ports_namespace = Namespace("docker", description='Endpoint to retrieve docker image exposed ports')


@docker_ports_namespace.route("", methods=['POST', 'GET'])
class DockerPortsAPI(Resource):
    """
    This is for creating Docker Challenges. The purpose of this API is to populate the Docker Image exposed ports Select form
    object in the Challenge Creation Screen.
    """

    @admins_only
    def get(self):
        image = request.args.get('image')
        docker = DockerConfig.query.filter_by(id=1).first()
        exposed_ports = list(get_required_ports(docker, image))
        return {
            'success': True,
            'data': exposed_ports
        }


def load(app):
    app.db.create_all()
    CHALLENGE_CLASSES['docker'] = DockerChallengeType
    register_plugin_assets_directory(app, base_path='/plugins/docker_challenges/assets')
    define_docker_admin(app)
    define_docker_status(app)
    CTFd_API_v1.add_namespace(docker_namespace, '/docker')
    CTFd_API_v1.add_namespace(docker_ports_namespace, '/docker_ports')
    CTFd_API_v1.add_namespace(container_namespace, '/container')
    CTFd_API_v1.add_namespace(active_docker_namespace, '/docker_status')
    CTFd_API_v1.add_namespace(kill_container, '/nuke')
