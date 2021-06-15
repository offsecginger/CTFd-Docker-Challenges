from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES, get_chal_class
from CTFd.plugins.flags import get_flag_class
from CTFd.utils.user import get_ip
from CTFd.utils.uploads import delete_file
from CTFd.plugins import register_plugin_assets_directory, bypass_csrf_protection
from CTFd.schemas.tags import TagSchema
from CTFd.models import db, ma, Challenges, Teams, Users, Solves, Fails, Flags, Files, Hints, Tags, ChallengeFiles
from CTFd.utils.decorators import admins_only, authed_only, during_ctf_time_only, require_verified_emails
from CTFd.utils.decorators.visibility import check_challenge_visibility, check_score_visibility
from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.user import is_admin, authed
from CTFd.utils.config import is_teams_mode
from CTFd.api import CTFd_API_v1
from CTFd.api.v1.scoreboard import ScoreboardDetail
import CTFd.utils.scores
from CTFd.api.v1.challenges import ChallengeList, Challenge
from flask_restx import Namespace, Resource
from flask import request, Blueprint, jsonify, abort, render_template, url_for, redirect, session
#from flask_wtf import FlaskForm
from wtforms import (
    FileField,
    HiddenField,
    PasswordField,
    RadioField,
    SelectField,
    StringField,
    TextAreaField,
    SelectMultipleField,
    BooleanField,
)
#from wtforms import TextField, SubmitField, BooleanField, HiddenField, FileField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, InputRequired
from werkzeug.utils import secure_filename
import docker
import requests
import tempfile
import os
from CTFd.utils.dates import unix_time
from datetime import datetime
import json
import hashlib
import random
from CTFd.plugins import register_admin_plugin_menu_bar

from CTFd.forms import BaseForm
from CTFd.forms.fields import SubmitField
from CTFd.utils.config import get_themes


class DockerConfig(db.Model):
	"""
	Docker Config Model. This model stores the config for docker API connections.
	"""
	id = db.Column(db.Integer, primary_key=True)
	hostname = db.Column("hostname",db.String(64), index=True)
	tls_enabled = db.Column("tls_enabled",db.Boolean,default=False, index=True)
	ca_cert = db.Column("ca_cert",db.Text)
	client_cert = db.Column("client_cert",db.Text)
	client_key = db.Column("client_key",db.Text)
	repositories = db.Column("repositories",db.Text)

class DockerChallengeTracker(db.Model):
	"""
	Docker Container Tracker. This model stores the users/teams active docker containers.
	"""
	id = db.Column(db.Integer, primary_key=True)
	team_id = db.Column("team_id",db.String(64), index=True)
	user_id = db.Column("user_id",db.String(64), index=True)
	docker_image = db.Column("docker_image",db.String(64), index=True)
	timestamp = db.Column("timestamp",db.Integer, index=True)
	revert_time = db.Column("revert_time",db.Integer, index=True)
	instance_id = db.Column("instance_id",db.String(64), index=True)
	ports = db.Column('ports', db.String(64), index=True)
	host = db.Column('host', db.String(64), index=True)


class DockerConfigForm(BaseForm):
    id = HiddenField()
    hostname = StringField(
        "Docker Hostname", description="The Hostname/IP and Port of your Docker Server"
    )
    tls_enabled = RadioField('TLS Enabled?')
    ca_cert = FileField('CA Cert')
    client_cert = FileField('Client Cert')
    client_key = FileField('Client Key')
    repositories = SelectMultipleField('Repositories')
    submit = SubmitField('Submit')


class DockerUploadForm(BaseForm):
    uploaded_file = FileField('docker_image')
    submit = SubmitField('Submit')


#Patch pour l'ajout d'image docker. Le petit soucis ici c'est qu'on utilise le SDK docker python au lieu de l'API Docker
#A modifier si cela pose probléme

def define_docker_upload(app) :
    admin_docker_upload = Blueprint('admin_docker_upload', __name__, template_folder='templates', static_folder='assets')
    @admin_docker_upload.route("/admin/docker_upload", methods=["GET", "POST"])
    @admins_only
    def docker_upload():
        form = DockerUploadForm()
        if request.method == "POST" :
            app.config['UPLOAD_FOLDER'] = 'CTFd/plugins/docker_challenges/docker_tar'
            file = request.files['docker_image']
            if file.filename != "" :
                # TODO:
                # WARNING: PAS DE SECURITE DANS LA GESTION DU NOM DU FICHIER !!!!!!
                # WARNING: IMPLEMENTER LA RECONNAISSANCE D'EXTENSION
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                try :

                    #Sauvegarde du tar terminé, on va maitenant importer l'image
                    client = docker.from_env()
                    image_tar = open(os.path.join(app.config['UPLOAD_FOLDER'], filename), "rb")
                    client.images.load(image_tar)

                except Exception as e :
                    print(e)


        return render_template('docker_upload.html', form = form)
    app.register_blueprint(admin_docker_upload )





def define_docker_admin(app):
	admin_docker_config = Blueprint('admin_docker_config', __name__, template_folder='templates', static_folder='assets')
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
			try: ca_cert = request.files['ca_cert'].stream.read()
			except: ca_cert = ''
			try: client_cert = request.files['client_cert'].stream.read()
			except: client_cert = ''
			try: client_key = request.files['client_key'].stream.read()
			except: client_key = ''
			if len(ca_cert) != 0: b.ca_cert = ca_cert
			if len(client_cert) != 0: b.client_cert = client_cert
			if len(client_key) != 0: b.client_key = client_key
			b.hostname = request.form['hostname']
			b.tls_enabled = request.form['tls_enabled']
			if b.tls_enabled == "True":
				b.tls_enabled = True
			else: b.tls_enabled = False
			if not b.tls_enabled:
				b.ca_cert = None
				b.client_cert = None
				b.client_key = None
			try: b.repositories = ','.join(request.form.to_dict(flat=False)['repositories'])
			except: b.repositories = None
			db.session.add(b)
			db.session.commit()
			docker = DockerConfig.query.filter_by(id=1).first()
		try:
			repos = get_repositories(docker)

		except:
			repos = list()
		if len(repos) == 0:
			form.repositories.choices = [("ERROR","Failed to Connect to Docker")]
		else:
			form.repositories.choices = [(d, d) for d in repos]
		dconfig = DockerConfig.query.first()
		try:
			selected_repos = dconfig.repositories
			if selected_repos == None:
				selected_repos = list()
			# selected_repos = dconfig.repositories.split(',')
			#Ajout de l'initialisation de la liste pour éviter l'erreur Nonetype lorsque la liste
			#N'est pas initialisée
			if selected_repos == None :
				selected_repos = []
		except:
			selected_repos = []
		return render_template("docker_config.html", config=dconfig, form=form, repos=selected_repos)
	app.register_blueprint(admin_docker_config)


def define_docker_status(app):
	admin_docker_status = Blueprint('admin_docker_status', __name__, template_folder='templates', static_folder='assets')
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
@kill_container.route("", methods=['POST','GET'])
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
			db.session.close()
		elif container != 'null' and container in [c.instance_id for c in docker_tracker]:
			delete_container(docker_config, container)
			DockerChallengeTracker.query.filter_by(instance_id=container).delete()
			db.session.commit()
			db.session.close()
		else:
			return False
		return True

# For the Docker Config Page. Gets the Current Repositories available on the Docker Server.
def get_repositories(docker, tags=False, repos=False):
	tls = docker.tls_enabled
	if not tls:
		prefix = 'http'
	else:
		prefix = 'https'

		try:
			#Modification de cette partie pour être compatible avec mysql
			ca = docker.ca_cert
			client = docker.client_cert
			ckey = docker.client_key
			ca_file = tempfile.NamedTemporaryFile(delete=False)
			ca_file.write(bytes(ca,'utf-8'))
			ca_file.seek(0)
			client_file = tempfile.NamedTemporaryFile(delete=False)
			client_file.write(bytes(client,'utf-8'))
			client_file.seek(0)
			key_file = tempfile.NamedTemporaryFile(delete=False)
			key_file.write(bytes(ckey,'utf-8'))
			key_file.seek(0)
			CERT = (client_file.name,key_file.name)
		except Exception as e :
			print(e)
			return []

	host = docker.hostname
	URL_TEMPLATE = '%s://%s' % (prefix, host)
	if tls:
		try:
			r = requests.get(url="%s/images/json?all=1" % URL_TEMPLATE, cert=CERT, verify=ca_file.name)
		except:
			return []
	else:
		try:
			r = requests.get(url="%s/images/json?all=1" % URL_TEMPLATE)
		except:
			return []
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
    tls = docker.tls_enabled
    if not tls:
        prefix = 'http'
    else:
        prefix = 'https'
        try:
            ca = docker.ca_cert
            client = docker.client_cert
            ckey = docker.client_key
            ca_file = tempfile.NamedTemporaryFile(delete=False)
            ca_file.write(ca.encode())
            ca_file.seek(0)
            client_file = tempfile.NamedTemporaryFile(delete=False)
            client_file.write(client.encode())
            client_file.seek(0)
            key_file = tempfile.NamedTemporaryFile(delete=False)
            key_file.write(ckey.encode())
            key_file.seek(0)
            CERT = (client_file.name,key_file.name)
        except:
            return []
    host = docker.hostname
    URL_TEMPLATE = '%s://%s' % (prefix, host)
    r = requests.get(url="%s/containers/json?all=1" % URL_TEMPLATE, cert=CERT, verify=ca_file.name)
    result = list()
    for i in r.json():
        #print(r.json())
        if not i['Ports'] == []:
            for p in i['Ports']:
                result.append(p['PublicPort'])
                return result

def get_required_ports(docker, image):
	tls = docker.tls_enabled
	if not tls:
		prefix = 'http'
	else:
		prefix = 'https'
		try:
			ca = docker.ca_cert
			client = docker.client_cert
			ckey = docker.client_key
			ca_file = tempfile.NamedTemporaryFile(delete=False)
			ca_file.write(bytes(ca,'utf-8'))
			ca_file.seek(0)
			client_file = tempfile.NamedTemporaryFile(delete=False)
			client_file.write(bytes(client,'utf-8'))
			client_file.seek(0)
			key_file = tempfile.NamedTemporaryFile(delete=False)
			key_file.write(bytes(ckey,'utf-8'))
			key_file.seek(0)
			CERT = (client_file.name,key_file.name)
		except:
			return []
	host = docker.hostname
	URL_TEMPLATE = '%s://%s' % (prefix, host)
	r = requests.get(url="%s/images/%s/json?all=1" % (URL_TEMPLATE, image), cert=CERT, verify=ca_file.name)
	result = r.json()['ContainerConfig']['ExposedPorts'].keys()
	return result


def create_container(docker, image, team, portbl):
    tls = docker.tls_enabled
    if not tls:
        prefix = 'http'
    else:
        prefix = 'https'
        try:
            ca = docker.ca_cert
            client = docker.client_cert
            ckey = docker.client_key
            ca_file = tempfile.NamedTemporaryFile(delete=False)
            ca_file.write(ca.encode())
            ca_file.seek(0)
            client_file = tempfile.NamedTemporaryFile(delete=False)
            client_file.write(client.encode())
            client_file.seek(0)
            key_file = tempfile.NamedTemporaryFile(delete=False)
            key_file.write(ckey.encode())
            key_file.seek(0)
            CERT = (client_file.name,key_file.name)
        except:
            return []
    host = docker.hostname
    URL_TEMPLATE = '%s://%s' % (prefix, host)
    needed_ports = get_required_ports(docker, image)
    team = hashlib.md5(team.encode("utf-8")).hexdigest()[:10]
    container_name = "%s_%s" % (image.split(':')[1], team)
    assigned_ports = dict()
    for i in needed_ports:
        # Ici j'ai ajouté un patch donnant la possibilité de lancer les conteneurs même si aucun conteneur n'est lancé
        while True:
            assigned_port = random.choice(range(30000,60000))
            if portbl == None :
                assigned_ports['%s/tcp' % assigned_port] = { }
                break
            if assigned_port not in portbl:
                assigned_ports['%s/tcp' % assigned_port] = { }
                break
    ports = dict()
    bindings = dict()
    tmp_ports = list(assigned_ports.keys())
    for i in needed_ports:
        ports[i] = { }
        bindings[i] = [{ "HostPort": tmp_ports.pop()}]
    headers = {'Content-Type': "application/json"}
    data = json.dumps({"Image": image, "ExposedPorts": ports, "HostConfig" : { "PortBindings" : bindings } })
    r = requests.post(url="%s/containers/create?name=%s" % (URL_TEMPLATE, container_name), cert=CERT, verify=ca_file.name, data=data, headers=headers)
    result = r.json()
    # Les conteneurs se suppriment maintenant
    # Les conteneurs sont automatiquement supprimés de la base de donnée
    print(result)
    if("message" in result) :
        if("Conflict" in result["message"]) :
            id = result["message"][82:146]
            delete_container(docker,id)
            DockerChallengeTracker.query.filter_by(instance_id=id).delete()
            docker_tracker = DockerChallengeTracker.query.all()

            db.session.commit()
            r = requests.post(url="%s/containers/create?name=%s" % (URL_TEMPLATE, container_name), cert=CERT, verify=ca_file.name, data=data, headers=headers)
            result = r.json()
            print(result)


    s = requests.post(url="%s/containers/%s/start" % (URL_TEMPLATE, result['Id']), cert=CERT, verify=ca_file.name, headers=headers)
    return result,data



def delete_container(docker, instance_id):
	tls = docker.tls_enabled
	if not tls:
		prefix = 'http'
	else:
		prefix = 'https'
		try:
			ca = docker.ca_cert
			client = docker.client_cert
			ckey = docker.client_key
			ca_file = tempfile.NamedTemporaryFile(delete=False)
			ca_file.write(bytes(ca,'utf-8'))
			ca_file.seek(0)
			client_file = tempfile.NamedTemporaryFile(delete=False)
			client_file.write(bytes(client,'utf-8'))
			client_file.seek(0)
			key_file = tempfile.NamedTemporaryFile(delete=False)
			key_file.write(bytes(ckey,'utf-8'))
			key_file.seek(0)
			CERT = (client_file.name,key_file.name)
		except:
			return []
	host = docker.hostname
	URL_TEMPLATE = '%s://%s' % (prefix, host)
	headers = {'Content-Type': "application/json"}
	r = requests.delete(url="%s/containers/%s?force=true" % (URL_TEMPLATE, instance_id), cert=CERT, verify=ca_file.name, headers=headers)
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

		#Pour bloquer le probléme de la suppression j'ai inversé les deux avant derniéres lignes afin de
		#respecter les contraintes des clefs étrangéres

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

    # TODO: Les challenges docker ne se solvent pas corréctement pour le moment

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
				docker_containers = DockerChallengeTracker.query.filter_by(docker_image=challenge.docker_image).filter_by(team_id=team.id).first()
			else:
				docker_containers = DockerChallengeTracker.query.filter_by(docker_image=challenge.docker_image).filter_by(user_id=user.id).first()
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
		db.session.close()

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
		db.session.close()

class DockerChallenge(Challenges):
    __mapper_args__ = {'polymorphic_identity': 'docker'}
    id = db.Column(None, db.ForeignKey('challenges.id'), primary_key=True)
    docker_image = db.Column(db.String(64), index=True)
    file_data = ""

# API
container_namespace = Namespace("container", description='Endpoint to interact with containers')
@container_namespace.route("", methods=['POST','GET'])
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
        # TODO: On peu aussi ajouter la suppression ici ça devrais être plus propre
		create = create_container(docker,container,session.name,portsbl)

		ports = json.loads(create[1])['HostConfig']['PortBindings'].values()
		entry = DockerChallengeTracker(
			team_id = session.id if is_teams_mode() else None,
			user_id = session.id if not is_teams_mode() else None,
			docker_image = container,
			timestamp = unix_time(datetime.utcnow()),
			revert_time = unix_time(datetime.utcnow()) + 300,
			instance_id = create[0]['Id'],
			ports = ','.join([p[0]['HostPort'] for p in ports]),
			host = str(docker.hostname).split(':')[0]
		)
		db.session.add(entry)
		db.session.commit()
		db.session.close()
		return

active_docker_namespace = Namespace("docker", description='Endpoint to retrieve User Docker Image Status')
@active_docker_namespace.route("", methods=['POST','GET'])
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
				'id' : i.id,
				'team_id' : i.team_id,
				'user_id' : i.user_id,
				'docker_image' : i.docker_image,
				'timestamp' : i.timestamp,
				'revert_time' : i.revert_time,
				'instance_id' : i.instance_id,
				'ports' : i.ports.split(','),
				'host' : str(docker.hostname).split(':')[0]
				})
		return {
					'success' : True,
					'data' : data
			}

docker_namespace = Namespace("docker", description='Endpoint to retrieve dockerstuff')
@docker_namespace.route("", methods=['POST','GET'])
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
				data.append({'name':i})
			return {
					'success' : True,
					'data' : data
			}
		else:
			return {
					'success' : False,
					'data' : [
							{
								'name':'Error in Docker Config!'
							}
						]
			}, 400

def load(app):
    app.db.create_all()
    CHALLENGE_CLASSES['docker'] = DockerChallengeType
    register_plugin_assets_directory(app, base_path='/plugins/docker_challenges/assets')
    define_docker_admin(app)
    define_docker_status(app)
    define_docker_upload(app)
    CTFd_API_v1.add_namespace(docker_namespace, '/docker')
    CTFd_API_v1.add_namespace(container_namespace, '/container')
    CTFd_API_v1.add_namespace(active_docker_namespace, '/docker_status')
    CTFd_API_v1.add_namespace(kill_container, '/nuke')
