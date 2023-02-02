import traceback
import random
import string
import boto3

from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES, get_chal_class
from CTFd.plugins.flags import get_flag_class
from CTFd.utils.user import get_ip
from CTFd.utils.uploads import delete_file
from CTFd.plugins import register_plugin_assets_directory, bypass_csrf_protection
from CTFd.schemas.tags import TagSchema
from CTFd.models import (
    db,
    ma,
    Challenges,
    Teams,
    Users,
    Solves,
    Fails,
    Flags,
    Files,
    Hints,
    Tags,
    ChallengeFiles,
)
from CTFd.utils.decorators import (
    admins_only,
    authed_only,
    during_ctf_time_only,
    require_verified_emails,
)
from CTFd.utils.decorators.visibility import (
    check_challenge_visibility,
    check_score_visibility,
)
from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.user import is_admin, authed
from CTFd.utils.config import is_teams_mode
from CTFd.api import CTFd_API_v1
from CTFd.api.v1.scoreboard import ScoreboardDetail
import CTFd.utils.scores
from CTFd.api.v1.challenges import ChallengeList, Challenge
from flask_restx import Namespace, Resource
from flask import (
    request,
    Blueprint,
    jsonify,
    abort,
    render_template,
    url_for,
    redirect,
    session,
)

# from flask_wtf import FlaskForm
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

# from wtforms import TextField, SubmitField, BooleanField, HiddenField, FileField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, InputRequired
from werkzeug.utils import secure_filename
import requests
import tempfile
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
    repositories = db.Column("repositories", db.String(1024))

    active_vpc = db.Column("active_vpc", db.String(64), index=True)

    aws_access_key_id = db.Column("aws_access_key_id", db.String(20))
    aws_secret_access_key = db.Column("aws_secret_access_key", db.String(40))
    cluster = db.Column("cluster", db.String(128))

    subnets = db.Column("subnets", db.String(1024))
    security_groups = db.Column("security_groups", db.String(1024))

    region = db.Column("region", db.String(32))


class DockerChallengeTracker(db.Model):
    """
    Docker Container Tracker. This model stores the users/teams active docker containers.
    """

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column("team_id", db.String(64), index=True)
    docker_image = db.Column("docker_image", db.String(128), index=True)
    challenge_id = db.Column("challenge_id", db.Integer, index=True)
    timestamp = db.Column("timestamp", db.Integer, index=True)
    revert_time = db.Column("revert_time", db.Integer, index=True)
    instance_id = db.Column("instance_id", db.String(128), index=True)
    ports = db.Column("ports", db.String(128), index=True)
    host = db.Column("host", db.String(128), index=True)
    flag = db.Column("flag", db.String(128), index=True)


class DockerConfigForm(BaseForm):
    id = HiddenField()
    aws_access_key_id = StringField(
        "AWS Access Key ID", description="The Access Key ID for your AWS account"
    )
    aws_secret_access_key = StringField(
        "AWS Secret Access Key",
        description="The Secret Access Key for your AWS account",
    )
    cluster = StringField(
        "Cluster", description="The ECS Cluster to run the challenges within"
    )
    repositories = SelectMultipleField("Repositories")
    vpcs = SelectMultipleField("VPC")
    submit = SubmitField("Submit")


def define_docker_admin(app):
    admin_docker_config = Blueprint(
        "admin_docker_config",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

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
            b.aws_access_key_id = request.form["aws_access_key_id"]
            b.aws_secret_access_key = request.form["aws_secret_access_key"]
            b.cluster = request.form["cluster"]
            try:
                b.repositories = ",".join(
                    request.form.to_dict(flat=False)["repositories"]
                )
            except:
                print(traceback.print_exc())
                b.repositories = None
            try:
                b.active_vpc = request.form.to_dict(flat=False)["active_vpc"][0]
            except:
                print(traceback.print_exc())
                b.active_vpc = None

            # Fetch the subnets and security groups associated with this VPC

            if b.active_vpc is not None:
                b.subnets = ",".join(get_subnets(b, b.active_vpc))
                b.security_groups = ",".join(get_security_groups(b, b.active_vpc))

            db.session.add(b)
            db.session.commit()
            docker = DockerConfig.query.filter_by(id=1).first()

        try:
            repos = get_repositories(docker)
        except:
            print(traceback.print_exc())
            repos = list()
        if len(repos) == 0:
            form.repositories.choices = [("ERROR", "Failed to connect to AWS")]
        else:
            form.repositories.choices = [(d, d) for d in repos]

        try:
            vpcs = get_vpcs(docker)
        except:
            print(traceback.print_exc())
            vpcs = list()
        if len(vpcs) == 0:
            form.vpcs.choices = [("ERROR", "Failed to connect to AWS")]
        else:
            form.vpcs.choices = [(d, d) for d in vpcs]

        dconfig = DockerConfig.query.first()
        try:
            selected_repos = dconfig.repositories
            if selected_repos == None:
                selected_repos = list()
        except:
            print(traceback.print_exc())
            selected_repos = []

        try:
            active_vpc = docker.active_vpc
        except:
            active_vpc = None

        return render_template(
            "docker_config.html",
            config=dconfig,
            form=form,
            repos=selected_repos,
            active_vpc=active_vpc,
        )

    app.register_blueprint(admin_docker_config)


def define_docker_status(app):
    admin_docker_status = Blueprint(
        "admin_docker_status",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

    @admin_docker_status.route("/admin/docker_status", methods=["GET", "POST"])
    @admins_only
    def docker_admin():
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        for i in docker_tracker:
            if is_teams_mode():
                name = Teams.query.filter_by(id=i.owner_id).first()
                i.owner_id = name.name
            else:
                name = Users.query.filter_by(id=i.owner_id).first()
                i.owner_id = name.name
        return render_template("admin_docker_status.html", dockers=docker_tracker)

    app.register_blueprint(admin_docker_status)


kill_container = Namespace("nuke", description="Endpoint to nuke containers")


@kill_container.route("", methods=["POST", "GET"])
class KillContainerAPI(Resource):
    @admins_only
    def get(self):
        container = request.args.get("container")
        full = request.args.get("all")
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        if full == "true":
            for c in docker_tracker:
                # delete_container(docker_config, c.instance_id)
                DockerChallengeTracker.query.filter_by(
                    instance_id=c.instance_id
                ).delete()
                db.session.commit()

        elif container != "null" and container in [
            c.instance_id for c in docker_tracker
        ]:
            # delete_container(docker_config, container)
            DockerChallengeTracker.query.filter_by(instance_id=container).delete()
            db.session.commit()

        else:
            return False
        return True


# For the Docker Config Page. Gets the Current Repositories available on the Docker Server.
def get_repositories(docker):
    ecs = boto3.client(
        "ecs",
        "eu-west-2",
        aws_access_key_id=docker.aws_access_key_id,
        aws_secret_access_key=docker.aws_secret_access_key,
    )

    taskDefs = ecs.list_task_definitions()

    print(taskDefs)

    return taskDefs["taskDefinitionArns"]


def get_vpcs(docker):
    ec2 = boto3.client(
        "ec2",
        "eu-west-2",
        aws_access_key_id=docker.aws_access_key_id,
        aws_secret_access_key=docker.aws_secret_access_key,
    )

    vpc_descr = ec2.describe_vpcs()
    print(vpc_descr)

    vpcs = [vpc["VpcId"] for vpc in vpc_descr["Vpcs"]]

    return vpcs


def get_subnets(docker, vpc):
    subnets = boto3.resource(
        "ec2",
        "eu-west-2",
        aws_access_key_id=docker.aws_access_key_id,
        aws_secret_access_key=docker.aws_secret_access_key,
    ).subnets.filter(Filters=[{"Name": "vpc-id", "Values": [vpc]}])
    return [sn.id for sn in subnets]


def get_security_groups(docker, vpc):
    security_groups = boto3.resource(
        "ec2",
        "eu-west-2",
        aws_access_key_id=docker.aws_access_key_id,
        aws_secret_access_key=docker.aws_secret_access_key,
    ).security_groups.filter(Filters=[{"Name": "vpc-id", "Values": [vpc]}])
    return [sg.id for sg in security_groups]


def create_container(docker, image, subnet, security_group, challenge_id, flag):
    ecs = boto3.client(
        "ecs",
        region_name="eu-west-2",
        aws_access_key_id=docker.aws_access_key_id,
        aws_secret_access_key=docker.aws_secret_access_key,
    )

    if is_teams_mode():
        session = get_current_team()
    else:
        session = get_current_user()

    owner = session.name

    owner = hashlib.md5(owner.encode("utf-8")).hexdigest()[:10]
    container_name = "%s_%s" % (image.replace(":", "-").replace("/", "-"), owner)
    print(container_name)

    # Get the flags on the challenge
    flags = Flags.query.filter_by(challenge_id=challenge_id).all()

    for flag in flags:
        if flag.type == "static":
            flag.content = flag.content.replace("{flag}", "{" + flag + "}")

    environment_variables = [
        f"FLAG_{idx}={flag.content}" for idx, flag in enumerate(flags)
    ]

    task = ecs.run_task(
        cluster=docker.cluster,
        taskDefinition=image,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "assignPublicIp": "DISABLED",
                "subnets": [subnet],
                "securityGroups": [security_group],
            }
        },
        overrides={
            "containerOverrides": [
                {
                    "name": "nginx",
                    "environment": [
                        {"name": f"FLAG_{idx}", "value": flag.content}
                        for idx, flag in enumerate(flags)
                    ],
                }
            ],
        },
    )

    print(task)
    return task


# def delete_container(docker, instance_id):
#    headers = {"Content-Type": "application/json"}
#    do_request(
#        docker,
#        f"/containers/{instance_id}?force=true",
#        headers=headers,
#        method="DELETE",
#    )
#    return True


class DockerChallengeType(BaseChallenge):
    id = "docker"
    name = "docker"
    templates = {
        "create": "/plugins/docker_challenges/assets/create.html",
        "update": "/plugins/docker_challenges/assets/update.html",
        "view": "/plugins/docker_challenges/assets/view.html",
    }
    scripts = {
        "create": "/plugins/docker_challenges/assets/create.js",
        "update": "/plugins/docker_challenges/assets/update.js",
        "view": "/plugins/docker_challenges/assets/view.js",
    }
    route = "/plugins/docker_challenges/assets"
    blueprint = Blueprint(
        "docker_challenges",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

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
            "id": challenge.id,
            "name": challenge.name,
            "value": challenge.value,
            "docker_image": challenge.docker_image,
            "description": challenge.description,
            "category": challenge.category,
            "state": challenge.state,
            "max_attempts": challenge.max_attempts,
            "type": challenge.type,
            "subnet": challenge.subnet,
            "security_group": challenge.security_group,
            "type_data": {
                "id": DockerChallengeType.id,
                "name": DockerChallengeType.name,
                "templates": DockerChallengeType.templates,
                "scripts": DockerChallengeType.scripts,
            },
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

        # Get the flag from the challenge the user is attempting
        if is_teams_mode():
            challengetracker = DockerChallengeTracker.query.filter_by(
                challenge_id=challenge.id, owner_id=get_current_team().id
            ).first()
        else:
            print(get_current_user().__dict__)
            challengetracker = DockerChallengeTracker.query.filter_by(
                challenge_id=challenge.id, owner_id=get_current_user().id
            ).first()

        if challengetracker is None:
            return False, "Failed to find challenge container!"

        print(challengetracker.flag)

        data = request.form or request.get_json()
        submission = data["submission"].strip()
        flags = Flags.query.filter_by(challenge_id=challenge.id).all()
        for flag in flags:
            # if get_flag_class(flag.type).compare(flag, submission):
            #    return True, "Correct"
            if flag.type == "static":
                print(flag.content)
                flag.content = flag.content.replace(
                    "{flag}", "{" + challengetracker.flag + "}"
                )

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
                docker_containers = (
                    DockerChallengeTracker.query.filter_by(
                        docker_image=challenge.docker_image
                    )
                    .filter_by(owner_id=team.id)
                    .first()
                )
            else:
                docker_containers = (
                    DockerChallengeTracker.query.filter_by(
                        docker_image=challenge.docker_image
                    )
                    .filter_by(owner_id=user.id)
                    .first()
                )
            # delete_container(docker, docker_containers.instance_id)
            DockerChallengeTracker.query.filter_by(
                instance_id=docker_containers.instance_id
            ).delete()
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
        # db.session.close()

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
        # db.session.close()


class DockerChallenge(Challenges):
    __mapper_args__ = {"polymorphic_identity": "docker"}
    id = db.Column(None, db.ForeignKey("challenges.id"), primary_key=True)
    docker_image = db.Column(db.String(128), index=True)
    subnet = db.Column(db.String(128), index=True)
    security_group = db.Column(db.String(128), index=True)


# API
container_namespace = Namespace(
    "container", description="Endpoint to interact with containers"
)


@container_namespace.route("", methods=["POST", "GET"])
class ContainerAPI(Resource):
    @authed_only
    # I wish this was Post... Issues with API/CSRF and whatnot. Open to a Issue solving this.
    def get(self):
        challenge_id = request.args.get("id")
        challenge = DockerChallenge.query.filter_by(id=challenge_id).first()
        if challenge is None:
            return abort(403)
        docker = DockerConfig.query.filter_by(id=1).first()
        containers = DockerChallengeTracker.query.all()
        if challenge.docker_image not in get_repositories(docker):
            return abort(403)
        if is_teams_mode():
            session = get_current_team()
        else:
            session = get_current_user()

            # First we'll delete all old docker containers (+2 hours)
            # for i in containers:
            #    if (
            #        int(session.id) == int(i.owner_id)
            #        and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200
            #    ):
            #        # delete_container(docker, i.instance_id)
            #        DockerChallengeTracker.query.filter_by(
            #            instance_id=i.instance_id
            #        ).delete()
            #        db.session.commit()
        check = (
            DockerChallengeTracker.query.filter_by(owner_id=session.id)
            .filter_by(challenge_id=challenge.id)
            .first()
        )

        # If this container is already created, we don't need another one.
        if (
            check != None
            and not (unix_time(datetime.utcnow()) - int(check.timestamp)) >= 300
        ):
            return abort(403)
        # The exception would be if we are reverting a box. So we'll delete it if it exists and has been around for more than 5 minutes.
        # elif check != None:
        #    # delete_container(docker, check.instance_id)
        #    if is_teams_mode():
        #        DockerChallengeTracker.query.filter_by(owner_id=session.id).filter_by(
        #            challenge_id=challenge.id
        #        ).delete()
        #    else:
        #        DockerChallengeTracker.query.filter_by(owner_id=session.id).filter_by(
        #            challenge_id=challenge.id
        #        ).delete()
        #    db.session.commit()
        # portsbl = get_unavailable_ports(docker)
        flag = "".join(random.choices(string.ascii_uppercase + string.digits, k=128))
        create = create_container(
            docker,
            challenge.docker_image,
            challenge.subnet,
            challenge.security_group,
            challenge_id,
            flag,
        )

        entry = DockerChallengeTracker(
            owner_id=session.id,
            challenge_id=challenge.id,
            docker_image=challenge.docker_image,
            timestamp=unix_time(datetime.utcnow()),
            revert_time=unix_time(datetime.utcnow()) + 300,
            instance_id=create["tasks"][0]["taskArn"],
            ports="",
            flag=flag,
        )

        print(flag)
        db.session.add(entry)
        db.session.commit()
        db.session.close()
        return


active_docker_namespace = Namespace(
    "docker", description="Endpoint to retrieve User Docker Image Status"
)


@active_docker_namespace.route("", methods=["POST", "GET"])
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
            tracker = DockerChallengeTracker.query.filter_by(owner_id=session.id)
        else:
            session = get_current_user()
            tracker = DockerChallengeTracker.query.filter_by(owner_id=session.id)
        data = list()
        for i in tracker:
            data.append(
                {
                    "id": i.id,
                    "owner_id": i.owner_id,
                    "challenge_id": i.challenge_id,
                    "timestamp": i.timestamp,
                    "revert_time": i.revert_time,
                    "instance_id": i.instance_id,
                    "ports": i.ports.split(","),
                }
            )
        return {"success": True, "data": data}


docker_namespace = Namespace("docker", description="Endpoint to retrieve dockerstuff")


@docker_namespace.route("", methods=["POST", "GET"])
class DockerAPI(Resource):
    """
    This is for creating Docker Challenges. The purpose of this API is to populate the Docker Image Select form
    object in the Challenge Creation Screen.
    """

    @admins_only
    def get(self):
        docker = DockerConfig.query.filter_by(id=1).first()
        images = get_repositories(docker)
        if images:
            data = list()
            for i in images:
                data.append({"name": i})
            return {"success": True, "data": data}
        else:
            return {
                "success": False,
                "data": [{"name": "Error in Docker Config!"}],
            }, 400


docker_config_namespace = Namespace(
    "docker_config",
    description="Endpoint for admins to be able to retreive information about the configuration",
)


@docker_config_namespace.route("", methods=["GET"])
class DockerConfigAPI(Resource):
    @admins_only
    def get(self):
        docker = DockerConfig.query.filter_by(id=1).first()

        if None not in [docker.subnets, docker.security_groups]:
            subnets = docker.subnets.split(",")
            security_groups = docker.security_groups.split(",")

            return {
                "success": True,
                "data": {"subnets": subnets, "security_groups": security_groups},
            }
        else:
            return {"success": False, "data": {}}


def load(app):
    app.db.create_all()
    CHALLENGE_CLASSES["docker"] = DockerChallengeType
    register_plugin_assets_directory(app, base_path="/plugins/docker_challenges/assets")
    define_docker_admin(app)
    define_docker_status(app)
    CTFd_API_v1.add_namespace(docker_namespace, "/docker")
    CTFd_API_v1.add_namespace(docker_config_namespace, "/docker_config")
    CTFd_API_v1.add_namespace(container_namespace, "/container")
    CTFd_API_v1.add_namespace(active_docker_namespace, "/docker_status")
    CTFd_API_v1.add_namespace(kill_container, "/nuke")
