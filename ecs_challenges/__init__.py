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

import os

from telnetlib import ENCRYPT
from datetime import datetime, timedelta
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode


GUACAMOLE_JSON_SECRET_KEY = os.environ["GUACAMOLE_JSON_SECRET_KEY"]


class guacamole:
    @staticmethod
    def encryptJWT(key, data):
        key = bytes.fromhex(key)
        h = HMAC.new(key, digestmod=SHA256)
        h.update(bytes(data, "UTF-8"))
        sig = h.digest()
        payload = sig + bytes(data, "UTF-8")
        iv = b"\0" * AES.block_size
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return b64encode(cipher.encrypt(pad(payload, AES.block_size)))

    @staticmethod
    def createJSON(ID, IP_ADDRESS):
        DATETIME = datetime.now() + timedelta(hours=2)
        TIMESTAMP = datetime.timestamp(DATETIME)
        payload = {
            "username": "",
            "expires": str(TIMESTAMP).split(".")[0] + "000",
            "connections": {
                ID: {
                    "protocol": "ssh",
                    "parameters": {
                        "hostname": IP_ADDRESS.strip(),
                        "username": "root",
                        "private-key": os.environ["GUACAMOLE_SSH_PRIVATE_KEY"],
                        "port": 22,
                        "proxy_hostname": "localhost",
                        "proxy_port": 4822,
                        "recording-path": "/tmp/recordings",
                        "recording-name": "My-Connection-${GUAC_USERNAME}-${GUAC_DATE}-${GUAC_TIME}",
                    },
                }
            },
        }
        return payload


class ECSConfig(db.Model):
    """
    ECS Config Model. This model stores the config for AWS connections and ECS cluster config.
    """

    id = db.Column(db.Integer, primary_key=True)
    repositories = db.Column("repositories", db.Text)

    active_vpc = db.Column("active_vpc", db.String(64), index=True)

    aws_access_key_id = db.Column("aws_access_key_id", db.String(20))
    aws_secret_access_key = db.Column("aws_secret_access_key", db.String(40))
    cluster = db.Column("cluster", db.String(128))

    subnets = db.Column("subnets", db.Text)
    security_groups = db.Column("security_groups", db.Text)

    region = db.Column("region", db.String(32))

    guacamole_address = db.Column("guacamole_address", db.String(128))

    guacamole_json_secret_key = db.Column("guacamole_json_secret_key", db.String(128))


class ECSChallengeTracker(db.Model):
    """
    ECS Task Tracker. This model stores the users/teams active ECS tasks.
    """

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column("team_id", db.String(64), index=True)
    task_definition = db.Column("task_definition", db.String(128), index=True)
    challenge_id = db.Column("challenge_id", db.Integer, index=True)
    timestamp = db.Column("timestamp", db.Integer, index=True)
    revert_time = db.Column("revert_time", db.Integer, index=True)
    instance_id = db.Column("instance_id", db.String(128), index=True)
    ports = db.Column("ports", db.String(128), index=True)
    host = db.Column("host", db.String(128), index=True)
    flag = db.Column("flag", db.String(128), index=True)


class ECSConfigForm(BaseForm):
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
    clusters = SelectMultipleField("VPC")
    vpcs = SelectMultipleField("VPC")
    submit = SubmitField("Submit")


def define_ecs_admin(app):
    admin_ecs_config = Blueprint(
        "admin_ecs_config",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

    @admin_ecs_config.route("/admin/ecs_config", methods=["GET", "POST"])
    @admins_only
    def ecs_config():
        ecs = ECSConfig.query.filter_by(id=1).first()
        form = ECSConfigForm()

        if request.method == "POST":
            if ecs:
                b = ecs
            else:
                b = ECSConfig()
            b.aws_access_key_id = request.form["aws_access_key_id"]
            b.aws_secret_access_key = request.form["aws_secret_access_key"]
            b.region = request.form["region"]
            b.repositories = json.dumps(get_repositories(b))

            b.guacamole_json_secret_key = request.form["guacamole_json_secret_key"]
            b.guacamole_address = request.form["guacamole_address"]

            try:
                b.cluster = request.form.to_dict(flat=False)["cluster"][0]
            except:
                print(traceback.print_exc())
                b.cluster = None

            try:
                b.active_vpc = request.form.to_dict(flat=False)["active_vpc"][0]
            except:
                print(traceback.print_exc())
                b.active_vpc = None

            # Fetch the subnets and security groups associated with this VPC

            if b.active_vpc is not None:
                b.subnets = json.dumps(get_subnets(b, b.active_vpc))
                b.security_groups = json.dumps(get_security_groups(b, b.active_vpc))

            db.session.add(b)
            db.session.commit()
            ecs = ECSConfig.query.filter_by(id=1).first()

        try:
            clusters = get_clusters(ecs)
        except:
            print(traceback.print_exc())
            clusters = list()

        if len(clusters) == 0:
            form.clusters.choices = [("ERROR", "Failed to connect to AWS")]
        else:
            form.clusters.choices = [(d, d) for d in clusters]

        try:
            vpcs = get_vpcs(ecs)
        except:
            print(traceback.print_exc())
            vpcs = list()
        if len(vpcs) == 0:
            form.vpcs.choices = [("ERROR", "Failed to connect to AWS")]
        else:
            form.vpcs.choices = [
                (d["value"], d["value"] + f" [{d['name']}]" if d["name"] else "")
                for d in vpcs
            ]

        dconfig = ECSConfig.query.first()
        if not dconfig:
            dconfig = ECSConfig()

        if dconfig.guacamole_json_secret_key is None:
            if "GUACAMOLE_JSON_SECRET_KEY" in os.environ.keys():
                dconfig.guacamole_json_secret_key = os.environ[
                    "GUACAMOLE_JSON_SECRET_KEY"
                ]

        if dconfig.guacamole_address is None:
            if "GUACAMOLE_ADDRESS" in os.environ.keys():
                dconfig.guacamole_address = os.environ["GUACAMOLE_ADDRESS"]

        try:
            active_vpc = ecs.active_vpc
        except:
            active_vpc = None

        try:
            cluster = ecs.cluster
        except:
            cluster = None

        return render_template(
            "ecs_config.html",
            config=dconfig,
            form=form,
            active_vpc=active_vpc,
            cluster=cluster,
        )

    app.register_blueprint(admin_ecs_config)


def define_ecs_status(app):
    admin_ecs_status = Blueprint(
        "admin_ecs_status",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

    @admin_ecs_status.route("/admin/ecs_status", methods=["GET", "POST"])
    @admins_only
    def ecs_admin():
        ecs_tasks = ECSChallengeTracker.query.all()
        for i in ecs_tasks:
            if is_teams_mode():
                name = Teams.query.filter_by(id=i.owner_id).first()
                i.owner_id = name.name
            else:
                name = Users.query.filter_by(id=i.owner_id).first()
                i.owner_id = name.name
        return render_template("admin_ecs_status.html", tasks=ecs_tasks)

    app.register_blueprint(admin_ecs_status)


kill_task = Namespace("nuke", description="Endpoint to nuke tasks")


@kill_task.route("", methods=["POST", "GET"])
class KillTaskAPI(Resource):
    @admins_only
    def get(self):
        task = request.args.get("task")
        full = request.args.get("all")
        ecs_config = ECSConfig.query.filter_by(id=1).first()
        ecs_tracker = ECSChallengeTracker.query.all()
        if full == "true":
            for c in ecs_tracker:
                stop_task(ecs_config, c.instance_id)
                ECSChallengeTracker.query.filter_by(instance_id=c.instance_id).delete()
                db.session.commit()

        elif task != "null" and task in [c.instance_id for c in ecs_tracker]:
            stop_task(ecs_config, task)
            ECSChallengeTracker.query.filter_by(instance_id=task).delete()
            db.session.commit()

        else:
            return False
        return True


# For the ECS Config Page. Gets the list of task definitions available on the ECS cluster.
def get_repositories(ecs):
    ecs_client = boto3.client(
        "ecs",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
    )

    taskDefs = ecs_client.list_task_definitions()

    return taskDefs["taskDefinitionArns"]


def get_clusters(ecs):
    ecs_client = boto3.client(
        "ecs",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
    )

    return ecs_client.list_clusters()["clusterArns"]


def get_vpcs(ecs):
    ec2_client = boto3.client(
        "ec2",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
    )

    vpc_descr = ec2_client.describe_vpcs()

    vpcs = vpc_descr["Vpcs"]

    return [
        {
            "value": vpc["VpcId"],
            "name": tags[0]["Value"]
            if len(tags := list(filter(lambda tag: tag["Key"] == "Name", vpc["Tags"])))
            else "",
        }
        for vpc in vpcs
    ]


def get_subnets(ecs, vpc):
    ec2_client = boto3.client(
        "ec2",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
    )

    subnets = filter(
        lambda subnet: subnet["VpcId"] == vpc,
        ec2_client.describe_subnets()["Subnets"],
    )

    return [
        {
            "value": sn["SubnetId"],
            "name": tags[0]["Value"]
            if len(tags := list(filter(lambda tag: tag["Key"] == "Name", sn["Tags"])))
            else "",
        }
        for sn in subnets
    ]


def get_security_groups(ecs, vpc):
    ec2_client = boto3.client(
        "ec2",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
    )

    security_groups = filter(
        lambda security_group: security_group["VpcId"] == vpc,
        ec2_client.describe_security_groups()["SecurityGroups"],
    )

    return [{"value": sg["GroupId"], "name": sg["GroupName"]} for sg in security_groups]


def get_address_of_task_container(ecs, task, container_name):
    ecs_client = boto3.client(
        "ecs",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
    )

    task = ecs_client.describe_tasks(cluster=ecs.cluster, tasks=[task])["tasks"][0]

    containers = task["containers"]

    container = list(
        filter(lambda container: container["name"] == container_name, containers)
    )[0]

    network_interfaces = container["networkInterfaces"]

    if len(network_interfaces) == 0:
        return None

    network_interface = network_interfaces[0]

    return network_interface["privateIpv4Address"]


def stop_task(ecs, task_id):
    ecs_client = boto3.client(
        "ecs",
        region_name=ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
    )

    ecs_client.stop_task(
        cluster=ecs.cluster, task=task_id, reason="Stopped by ECS CTFd Plugin"
    )


def create_task(
    ecs, task_definition, subnet, security_group, challenge_id, random_flag
):
    ecs_client = boto3.client(
        "ecs",
        region_name=ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
    )

    if is_teams_mode():
        session = get_current_team()
    else:
        session = get_current_user()

    owner = session.name

    owner = hashlib.md5(owner.encode("utf-8")).hexdigest()[:10]

    # Get the flags on the challenge
    flags = Flags.query.filter_by(challenge_id=challenge_id).all()

    challenge = ECSChallenge.query.filter_by(id=challenge_id).first()

    environment_variables = [
        (
            f"FLAG_{idx}",
            f"{flag.content if flag.type != 'static' else flag.content.replace('{flag}', f'{{{random_flag}}}')}",
        )
        for idx, flag in enumerate(flags)
    ]

    task = ecs_client.run_task(
        cluster=ecs.cluster,
        taskDefinition=task_definition,
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
                    "name": challenge.entrypoint_container,
                    "environment": [
                        {"name": name, "value": flag}
                        for (name, flag) in environment_variables
                    ],
                }
            ],
        },
        tags=[
            {"key": "ChallengeID", "value": f"{challenge_id}"},
            {"key": "OwnerID", "value": f"{session.id}"},
        ],
    )

    return task


class ECSChallengeType(BaseChallenge):
    id = "ecs"
    name = "ecs"
    templates = {
        "create": "/plugins/ecs_challenges/assets/create.html",
        "update": "/plugins/ecs_challenges/assets/update.html",
        "view": "/plugins/ecs_challenges/assets/view.html",
    }
    scripts = {
        "create": "/plugins/ecs_challenges/assets/create.js",
        "update": "/plugins/ecs_challenges/assets/update.js",
        "view": "/plugins/ecs_challenges/assets/view.js",
    }
    route = "/plugins/ecs_challenges/assets"
    blueprint = Blueprint(
        "ecs_challenges",
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
        NOTE: Will need to kill all tasks here

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
        ECSChallenge.query.filter_by(id=challenge.id).delete()
        Challenges.query.filter_by(id=challenge.id).delete()
        db.session.commit()

    @staticmethod
    def read(challenge):
        """
        This method is in used to access the data of a challenge in a format processable by the front end.

        :param challenge:
        :return: Challenge object, data dictionary to be returned to the user
        """
        challenge = ECSChallenge.query.filter_by(id=challenge.id).first()
        data = {
            "id": challenge.id,
            "name": challenge.name,
            "value": challenge.value,
            "task_definition": challenge.task_definition,
            "description": challenge.description,
            "category": challenge.category,
            "state": challenge.state,
            "max_attempts": challenge.max_attempts,
            "type": challenge.type,
            "subnet": challenge.subnet,
            "security_group": challenge.security_group,
            "type_data": {
                "id": ECSChallengeType.id,
                "name": ECSChallengeType.name,
                "templates": ECSChallengeType.templates,
                "scripts": ECSChallengeType.scripts,
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
        challenge = ECSChallenge(**data)
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

        # Get the flag from the challenge the user is attempting
        if is_teams_mode():
            challengetracker = ECSChallengeTracker.query.filter_by(
                challenge_id=challenge.id, owner_id=get_current_team().id
            ).first()
        else:
            challengetracker = ECSChallengeTracker.query.filter_by(
                challenge_id=challenge.id, owner_id=get_current_user().id
            ).first()

        if challengetracker is None:
            return False, "Failed to find challenge task!"

        print(challengetracker.flag)

        data = request.form or request.get_json()
        submission = data["submission"].strip()
        flags = Flags.query.filter_by(challenge_id=challenge.id).all()

        for flag in flags:
            if flag.type == "static":
                saved = flag.content.replace("{flag}", f"{{{challengetracker.flag}}}")
                data = flag.data

                if len(saved) != len(submission):
                    return False
                result = 0

                if data == "case_insensitive":
                    for x, y in zip(saved.lower(), submission.lower()):
                        result |= ord(x) ^ ord(y)
                else:
                    for x, y in zip(saved, submission):
                        result |= ord(x) ^ ord(y)

                if result == 0:
                    return True, "Correct"
                else:
                    return False, "Incorrect"

            else:
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
        ecs = ECSConfig.query.filter_by(id=1).first()
        try:
            if is_teams_mode():
                ecs_task = (
                    ECSChallengeTracker.query.filter_by(
                        task_definition=challenge.task_definition
                    )
                    .filter_by(owner_id=team.id)
                    .first()
                )
            else:
                ecs_task = (
                    ECSChallengeTracker.query.filter_by(
                        task_definition=challenge.task_definition
                    )
                    .filter_by(owner_id=user.id)
                    .first()
                )
            stop_task(ecs, ecs_task.instance_id)
            ECSChallengeTracker.query.filter_by(
                instance_id=ecs_task.instance_id
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


class ECSChallenge(Challenges):
    __mapper_args__ = {"polymorphic_identity": "ecs"}
    id = db.Column(None, db.ForeignKey("challenges.id"), primary_key=True)
    task_definition = db.Column(db.String(128), index=True)
    subnet = db.Column(db.String(128), index=True)
    security_group = db.Column(db.String(128), index=True)
    entrypoint_container = db.Column(db.String(128), index=True)


# API
task_namespace = Namespace("task", description="Endpoint to interact with tasks")


@task_namespace.route("", methods=["POST", "GET"])
class TaskAPI(Resource):
    @authed_only
    # I wish this was Post... Issues with API/CSRF and whatnot. Open to a Issue solving this.
    def get(self):
        challenge_id = request.args.get("id")
        challenge = ECSChallenge.query.filter_by(id=challenge_id).first()
        if challenge is None:
            return abort(403)
        ecs = ECSConfig.query.filter_by(id=1).first()
        tasks = ECSChallengeTracker.query.all()
        if challenge.task_definition not in get_repositories(ecs):
            return abort(403)
        if is_teams_mode():
            session = get_current_team()
        else:
            session = get_current_user()

            # First we'll delete all old docker containers (+2 hours)
            for i in tasks:
                if (
                    int(session.id) == int(i.owner_id)
                    and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200
                ):
                    stop_task(ecs, i.instance_id)
                    ECSChallengeTracker.query.filter_by(
                        instance_id=i.instance_id
                    ).delete()
                    db.session.commit()
        check = (
            ECSChallengeTracker.query.filter_by(owner_id=session.id)
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
        elif check != None:
            stop_task(ecs, check.instance_id)
            if is_teams_mode():
                ECSChallengeTracker.query.filter_by(owner_id=session.id).filter_by(
                    challenge_id=challenge.id
                ).delete()
            else:
                ECSChallengeTracker.query.filter_by(owner_id=session.id).filter_by(
                    challenge_id=challenge.id
                ).delete()
            db.session.commit()
        # portsbl = get_unavailable_ports(docker)
        flag = "".join(random.choices(string.ascii_uppercase + string.digits, k=128))
        create = create_task(
            ecs,
            challenge.task_definition,
            challenge.subnet,
            challenge.security_group,
            challenge_id,
            flag,
        )

        entry = ECSChallengeTracker(
            owner_id=session.id,
            challenge_id=challenge.id,
            task_definition=challenge.task_definition,
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


container_namespace = Namespace(
    "container",
    description="Fetch the containers for a given task definition",
)


@container_namespace.route("", methods=["GET"])
class ContainerFetcher(Resource):
    @authed_only
    def get(self):
        ecs = ECSConfig.query.filter_by(id=1).first()

        ecs_client = boto3.client(
            "ecs",
            ecs.region,
            aws_access_key_id=ecs.aws_access_key_id,
            aws_secret_access_key=ecs.aws_secret_access_key,
        )
        taskDefinition = request.args.get("taskDef")

        try:
            containers = [
                containerDef["name"]
                for containerDef in ecs_client.describe_task_definition(
                    taskDefinition=taskDefinition
                )["taskDefinition"]["containerDefinitions"]
            ]

            return {"success": True, "data": containers}

        except:
            return {"success": False, "data": []}


connect_namespace = Namespace(
    "connect",
    description="Allows users to retrieve a connection URL for the container to access it via Guacamole",
)


@connect_namespace.route("", methods=["GET"])
class JWTFetcher(Resource):
    @authed_only
    def get(self):
        ecs = ECSConfig.query.filter_by(id=1).first()

        if ecs.guacamole_address is None:
            return {"success": False, "data": []}

        challenge_id = request.args.get("id")
        challenge = ECSChallenge.query.filter_by(id=challenge_id).first()
        if challenge is None:
            return {"success": False, "data": []}

        # Get the ECSChallengeTracker for this container

        if is_teams_mode():
            session = get_current_team()
        else:
            session = get_current_user()

        container = ECSChallengeTracker.query.filter_by(
            challenge_id=challenge_id, owner_id=session.id
        ).first()
        if container is None:
            return {"success": False, "data": []}

        # Identify the IP address of the container

        address = get_address_of_task_container(
            ecs, container.instance_id, challenge.entrypoint_container
        )

        if address is None:
            return {"success": False, "data": []}

        print(address)

        # Create a JWT for this address to hand over to Guacamole

        payload = guacamole.createJSON(session.id, address)
        jwt = guacamole.encryptJWT(GUACAMOLE_JSON_SECRET_KEY, json.dumps(payload))

        return {"success": True, "data": [ecs.guacamole_address, jwt.decode("UTF-8")]}


active_ecs_namespace = Namespace(
    "ecs", description="Endpoint to retrieve User ECS Task Definition Status"
)


@active_ecs_namespace.route("", methods=["POST", "GET"])
class ECSStatus(Resource):
    """
    The Purpose of this API is to retrieve a public JSON string of all ECS tasks
    in use by the current team/user.
    """

    @authed_only
    def get(self):
        if is_teams_mode():
            session = get_current_team()
            tracker = ECSChallengeTracker.query.filter_by(owner_id=session.id)
        else:
            session = get_current_user()
            tracker = ECSChallengeTracker.query.filter_by(owner_id=session.id)
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


ecs_namespace = Namespace("ecs", description="Endpoint to retrieve ECS stuff")


@ecs_namespace.route("", methods=["POST", "GET"])
class ECSAPI(Resource):
    """
    This is for creating ECS Challenges. The purpose of this API is to populate the ECS Task Definition Select form
    object in the Challenge Creation Screen.
    """

    @admins_only
    def get(self):
        ecs = ECSConfig.query.filter_by(id=1).first()
        images = get_repositories(ecs)
        if images:
            data = list()
            for i in images:
                data.append({"name": i})
            return {"success": True, "data": data}
        else:
            return {
                "success": False,
                "data": [{"name": "Error in ECS Config!"}],
            }, 400


ecs_config_namespace = Namespace(
    "ecs_config",
    description="Endpoint for admins to be able to retreive information about the configuration",
)


@ecs_config_namespace.route("", methods=["GET"])
class ECSConfigAPI(Resource):
    @admins_only
    def get(self):
        ecs = ECSConfig.query.filter_by(id=1).first()

        if None not in [ecs.subnets, ecs.security_groups]:
            subnets = json.loads(ecs.subnets)
            security_groups = json.loads(ecs.security_groups)

            return {
                "success": True,
                "data": {"subnets": subnets, "security_groups": security_groups},
            }
        else:
            return {"success": False, "data": {}}


def load(app):
    app.db.create_all()
    CHALLENGE_CLASSES["ecs"] = ECSChallengeType
    register_plugin_assets_directory(app, base_path="/plugins/ecs_challenges/assets")
    define_ecs_admin(app)
    define_ecs_status(app)
    CTFd_API_v1.add_namespace(ecs_namespace, "/ecs")
    CTFd_API_v1.add_namespace(ecs_config_namespace, "/ecs_config")
    CTFd_API_v1.add_namespace(task_namespace, "/task")
    CTFd_API_v1.add_namespace(container_namespace, "/containers")
    CTFd_API_v1.add_namespace(connect_namespace, "/connect")
    CTFd_API_v1.add_namespace(active_ecs_namespace, "/ecs_status")
    CTFd_API_v1.add_namespace(kill_task, "/nuke")
