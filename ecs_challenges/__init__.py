import traceback
import random
import string
import boto3

from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES, get_chal_class
from CTFd.plugins.flags import get_flag_class
from CTFd.utils.user import get_ip
from CTFd.utils.uploads import delete_file
from CTFd.utils import get_config
from CTFd.plugins import register_plugin_assets_directory, bypass_csrf_protection
from CTFd.plugins.migrations import upgrade
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
import uuid

from .models import *
from .guacamole_viewer import define_guacamole_viewer

GUACAMOLE_JSON_SECRET_KEY = os.environ.get("GUACAMOLE_JSON_SECRET_KEY")


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
    def createJSON(ID, IP_ADDRESS, PROTOCOL, RECORDING_NAME):
        DATETIME = datetime.now() + timedelta(hours=2)
        TIMESTAMP = datetime.timestamp(DATETIME)
        if PROTOCOL == "ssh":
            payload = {
                "username": "",
                "expires": str(TIMESTAMP).split(".")[0] + "000",
                "connections": {
                    ID: {
                        "protocol": "ssh",
                        "parameters": {
                            "hostname": IP_ADDRESS.strip(),
                            "username": "punk",
                            "private-key": os.environ.get(
                                "GUACAMOLE_SSH_PRIVATE_KEY", ""
                            ),
                            "port": 22,
                            "proxy_hostname": "localhost",
                            "proxy_port": 4822,
                            "recording-path": "/recordings",
                            "recording-name": RECORDING_NAME,
                        },
                    }
                },
            }
        elif PROTOCOL == "vnc":
            payload = {
                "username": "",
                "expires": str(TIMESTAMP).split(".")[0] + "000",
                "connections": {
                    ID: {
                        "protocol": "vnc",
                        "parameters": {
                            "hostname": IP_ADDRESS.strip(),
                            "port": 5900,
                            "proxy_hostname": "localhost",
                            "proxy_port": 4822,
                            "recording-path": "/recordings",
                            "recording-name": RECORDING_NAME,
                        },
                    }
                },
            }
        return payload


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
    clusters = SelectField("Clusters")
    vpcs = SelectField("VPC")
    guacamole_address = StringField(
        "Guacamole Address", description="Address for connecting to guacamole"
    )
    guacamole_json_secret_key = StringField(
        "Guacamole JSON Secret Key",
        description="Secret key for encrypting the Guacamole JWT",
    )
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
            ecs.aws_access_key_id = request.form["aws_access_key_id"] or None
            ecs.aws_secret_access_key = request.form["aws_secret_access_key"] or None
            ecs.region = request.form["region"]
            ecs.task_definitions = json.dumps(get_task_definitions(ecs))

            ecs.guacamole_json_secret_key = (
                request.form["guacamole_json_secret_key"] or None
            )
            ecs.guacamole_address = request.form["guacamole_address"] or None

            ecs.active_vpc = request.form.to_dict(flat=False).get("active_vpc")[0]

            ecs.filter_tag = request.form.to_dict(flat=False).get("filter_tag")[0]

            ecs.guide_enabled = "true" == request.form.get("guide_enabled", False)

            # Fetch the subnets and security groups associated with this VPC

            if ecs.active_vpc is not None:
                ecs.subnets = json.dumps(get_subnets(ecs, ecs.active_vpc))
                ecs.security_groups = json.dumps(
                    get_security_groups(ecs, ecs.active_vpc)
                )

            db.session.add(ecs)
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

        return render_template(
            "ecs_config.html",
            config=ecs,
            form=form,
            active_vpc=ecs.active_vpc,
            cluster=ecs.cluster,
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
        id_name_map = {}
        for i in ecs_tasks:
            name = Users.query.filter_by(id=i.owner_id).first()
            id_name_map[i.owner_id] = name.name if name else "[User Removed]"
        return render_template(
            "admin_ecs_status.html", tasks=ecs_tasks, id_name_map=id_name_map
        )

    app.register_blueprint(admin_ecs_status)


def define_ecs_history(app):
    admin_ecs_history = Blueprint(
        "admin_ecs_history",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

    @admin_ecs_history.route("/admin/ecs_history", methods=["GET", "POST"])
    @admins_only
    def ecs_history():
        ecs = ECSConfig.query.first()

        last_id = request.args.get("last_id")
        user_id = request.args.get("user_id")
        challenge_id = request.args.get("challenge_id")
        query = ECSHistory.query
        if user_id:
            query = query.filter_by(user_id=user_id)
        if challenge_id:
            query = query.filter_by(challenge_id=challenge_id)
        if last_id:
            query = query.filter(ECSHistory.id < last_id)

        entries = query.order_by(ECSHistory.id.desc()).limit(20).all()

        if len(entries) == 20:
            next_page_id = entries[len(entries) - 1].id
        else:
            next_page_id = None

        if (
            last_id
            and not ECSHistory.query.order_by(ECSHistory.id.desc()).first().id
            == int(last_id) - 1
        ):
            last_page_id = entries[0].id + 21
        else:
            last_page_id = None

        id_name_map = {}
        id_challenge_map = {}
        for i in entries:
            name = Users.query.filter_by(id=i.user_id).first()
            id_name_map[i.user_id] = name.name if name else "[User Removed]"
        for i in entries:
            challenge = ECSChallenge.query.filter_by(id=i.challenge_id).first()
            id_challenge_map[i.challenge_id] = (
                challenge.name if challenge else "[Challenge Removed]"
            )
        return render_template(
            "admin_ecs_history.html",
            guacamole_address=ecs.guacamole_address,
            entries=entries,
            id_name_map=id_name_map,
            id_challenge_map=id_challenge_map,
            last_page_id=last_page_id,
            next_page_id=next_page_id,
        )

    # This implements the actual history viewer which we will open in a separate window.
    @admin_ecs_history.route("/admin/ecs_history_viewer", methods=["GET", "POST"])
    @admins_only
    def ecs_history_viewer():
        ecs = ECSConfig.query.first()

        return render_template(
            "admin_ecs_history_viewer.html",
            guacamole_address=ecs.guacamole_address,
            filename=request.args.get("filename"),
        )

    app.register_blueprint(admin_ecs_history)


kill_task = Namespace("nuke", description="Endpoint to nuke tasks")


@kill_task.route("", methods=["POST", "GET"])
class KillTaskAPI(Resource):
    @authed_only
    def get(self):
        task = request.args.get("task")
        full = request.args.get("all")
        ecs_config = ECSConfig.query.filter_by(id=1).first()
        ecs_tracker = ECSChallengeTracker.query.all()
        if full == "true" and is_admin():
            for c in ecs_tracker:
                try:
                    stop_task(ecs_config, c.instance_id)
                except:
                    pass
                ECSChallengeTracker.query.filter_by(instance_id=c.instance_id).delete()
                db.session.commit()

        elif task != "null" and task in [c.instance_id for c in ecs_tracker]:
            if is_admin():
                try:
                    stop_task(ecs_config, task)
                except:
                    pass
                ECSChallengeTracker.query.filter_by(instance_id=task).delete()
                db.session.commit()
            else:
                session = get_current_user()

                challenge = ECSChallengeTracker.query.filter_by(
                    instance_id=task
                ).first()
                if int(challenge.owner_id) == session.id:
                    stop_task(ecs_config, task)
                    ECSChallengeTracker.query.filter_by(instance_id=task).delete()
                    db.session.commit()
                else:
                    return False

        else:
            return False
        return True


# For the ECS Config Page. Gets the list of task definitions available on the ECS cluster.
def get_task_definitions(ecs):
    ecs_client = boto3.client(
        "ecs",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
    )

    taskDefs = [
        ecs_client.describe_task_definition(taskDefinition=arn, include=["TAGS"])
        for arn in ecs_client.list_task_definitions()["taskDefinitionArns"]
    ]

    return [
        taskDef["taskDefinition"]["taskDefinitionArn"]
        for taskDef in taskDefs
        if not ecs.filter_tag
        or len(list(filter(lambda tag: tag["key"] == ecs.filter_tag, taskDef["tags"])))
    ]


def get_clusters(ecs):
    ecs_client = boto3.client(
        "ecs",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
    )

    clusters = ecs_client.describe_clusters(
        clusters=ecs_client.list_clusters()["clusterArns"], include=["TAGS"]
    )["clusters"]

    return [cluster["clusterArn"] for cluster in clusters]


def get_vpcs(ecs):
    ec2_client = boto3.client(
        "ec2",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
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
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
    )

    subnets = [
        subnet
        for subnet in ec2_client.describe_subnets(
            Filters=[{"Name": "tag-key", "Values": [ecs.filter_tag]}]
            if ecs.filter_tag
            else []
        )["Subnets"]
        if subnet["VpcId"] == vpc
    ]

    return [
        {
            "value": subnet["SubnetId"],
            "name": tags[0]["Value"]
            if len(
                tags := list(filter(lambda tag: tag["Key"] == "Name", subnet["Tags"]))
            )
            else "",
        }
        for subnet in subnets
    ]


def get_security_groups(ecs, vpc):
    ec2_client = boto3.client(
        "ec2",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
    )

    security_groups = [
        security_group
        for security_group in ec2_client.describe_security_groups(
            Filters=[{"Name": "tag-key", "Values": [ecs.filter_tag]}]
            if ecs.filter_tag
            else []
        )["SecurityGroups"]
        if security_group["VpcId"] == vpc
    ]

    return [
        {"value": security_group["GroupId"], "name": security_group["GroupName"]}
        for security_group in security_groups
    ]


def get_address_of_task_container(ecs, task, container_name):
    ecs_client = boto3.client(
        "ecs",
        ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
    )

    task = ecs_client.describe_tasks(cluster=ecs.cluster, tasks=[task])["tasks"][0]

    if ecs.guacamole_address:
        containers = task["containers"]

        container = list(
            filter(lambda container: container["name"] == container_name, containers)
        )[0]

        network_interfaces = container["networkInterfaces"]

        if len(network_interfaces) == 0:
            return None

        network_interface = network_interfaces[0]

        return network_interface["privateIpv4Address"]
    else:
        attachments = task["attachments"]

        eni = list(
            filter(
                lambda attachment: attachment["type"] == "ElasticNetworkInterface",
                attachments,
            )
        )[0]

        details = eni["details"]

        eni_id = list(
            filter(lambda detail: detail["name"] == "networkInterfaceId", details)
        )[0]["value"]

        eni = boto3.resource(
            "ec2",
            ecs.region,
            aws_access_key_id=ecs.aws_access_key_id,
            aws_secret_access_key=ecs.aws_secret_access_key,
            aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
        ).NetworkInterface(eni_id)

        return eni.association_attribute["PublicIp"]


def stop_task(ecs, task_id):
    ecs_client = boto3.client(
        "ecs",
        region_name=ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
    )

    ecs_client.stop_task(
        cluster=ecs.cluster, task=task_id, reason="Stopped by ECS CTFd Plugin"
    )

    task = ecs_client.describe_tasks(tasks=[task_id], cluster=ecs.cluster)["tasks"][0]

    print("Here")
    if "containerInstanceArn" in task.keys():
        print("Here2")
        container_instance = ecs_client.describe_container_instances(
            containerInstances=[task["containerInstanceArn"]], cluster=ecs.cluster
        )["containerInstances"][0]

        ec2_client = boto3.client(
            "ec2",
            region_name=ecs.region,
            aws_access_key_id=ecs.aws_access_key_id,
            aws_secret_access_key=ecs.aws_secret_access_key,
            aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
        )

        ec2_client.terminate_instances(
            InstanceIds=[container_instance["ec2InstanceId"]]
        )


def create_task(
    ecs, task_definition, subnets, security_group, challenge_id, random_flag
):
    ecs_client = boto3.client(
        "ecs",
        region_name=ecs.region,
        aws_access_key_id=ecs.aws_access_key_id,
        aws_secret_access_key=ecs.aws_secret_access_key,
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
    )

    session = get_current_user()

    owner = session.name

    owner = hashlib.md5(owner.encode("utf-8")).hexdigest()[:10]

    # Get the flags on the challenge
    flags = Flags.query.filter_by(challenge_id=challenge_id).all()

    challenge = ECSChallenge.query.filter_by(id=challenge_id).first()

    # First we should check if the user already has a running task
    if not is_admin():
        if len(ECSChallengeTracker.query.filter_by(owner_id=session.id).all()):
            tracker = ECSChallengeTracker.query.filter_by(owner_id=session.id).first()
            challenge = ECSChallenge.query.filter_by(id=tracker.challenge_id).first()
            return False, [
                "You already have a running task!",
                challenge.name,
                tracker.challenge_id,
                tracker.instance_id,
            ]

    # Prevent starting a task if the user/team has a solve on this challenge already
    if not is_admin():
        if is_teams_mode():
            if len(
                Solves.query.filter_by(
                    challenge_id=challenge.id, team_id=get_current_team().id
                ).all()
            ):
                return False, ["You have already solved this task!"]
        else:
            if len(
                Solves.query.filter_by(
                    challenge_id=challenge.id, user_id=get_current_user().id
                ).all()
            ):
                return False, ["You have already solved this task!"]

    # Prevent users from starting tasks when the CTF is paused
    if not is_admin() and get_config("paused", 0) == 1:
        return False, ["Cannot start challenges whilst CTF is paused!"]

    environment_variables = [
        (
            f"FLAG_{idx}",
            f"{flag.content if flag.type != 'static' else flag.content.replace('{flag}', f'{{{random_flag}}}')}",
        )
        for idx, flag in enumerate(flags)
    ]

    flag_containers = json.loads(challenge.flag_containers)

    if challenge.ssh_container in flag_containers:
        environment_variables.append(
            ("SSH_KEY", os.environ.get("CONTAINER_SSH_PUBLIC_KEY", ""))
        )

    try:
        aws_response = ecs_client.run_task(
            cluster=ecs.cluster,
            taskDefinition=task_definition,
            launchType="FARGATE" if challenge.launch_type == "fargate" else "EC2",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "assignPublicIp": "DISABLED"
                    if ecs.guacamole_address
                    else "ENABLED",
                    "subnets": subnets,
                    "securityGroups": [security_group],
                }
            },
            overrides={
                "containerOverrides": [
                    {
                        "name": container,
                        "environment": [
                            {"name": name, "value": flag}
                            for (name, flag) in environment_variables
                        ],
                    }
                    for container in flag_containers
                ]
                + (
                    [
                        {
                            "name": challenge.ssh_container,
                            "environment": [
                                {
                                    "name": "SSH_KEY",
                                    "value": os.environ.get(
                                        "CONTAINER_SSH_PUBLIC_KEY", ""
                                    ),
                                }
                            ],
                        }
                    ]
                    if challenge.ssh_container
                    and challenge.ssh_container not in flag_containers
                    else []
                ),
            },
            tags=[
                {"key": "ChallengeID", "value": f"{challenge_id}"},
                {"key": "OwnerID", "value": f"{session.id}"},
            ],
            placementConstraints=[{"type": "distinctInstance"}]
            if challenge.launch_type == "ec2"
            else [],
        )
    except Exception as e:
        print("Failed to start challenge! (Call to run_task threw!)")
        print(repr(e))
        return False, ["Internal server error!"]

    if any(aws_response["tasks"]):
        return True, aws_response
    else:
        print(
            "Failed to start challenge! (AWS response returned an empty list of created tasks)"
        )
        return False, ["Internal server error!"]


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
        ecs = ECSConfig.query.filter_by(id=1).first()

        data = request.form or request.get_json()
        if "subnets" in data.keys():
            data["subnets"] = json.dumps(data["subnets"])
        if "flag_containers" in data.keys():
            data["flag_containers"] = json.dumps(data["flag_containers"])

        # Discover ssh_container and vnc_container

        ecs_client = boto3.client(
            "ecs",
            ecs.region,
            aws_access_key_id=ecs.aws_access_key_id,
            aws_secret_access_key=ecs.aws_secret_access_key,
            aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
        )

        if data.get("task_definition"):
            taskDefinition = data["task_definition"]
            containerDefs = ecs_client.describe_task_definition(
                taskDefinition=taskDefinition
            )["taskDefinition"]["containerDefinitions"]

            containerMappings = {}

            for containerDef in containerDefs:
                if portMappings := containerDef.get("portMappings", []):
                    for portMapping in portMappings:
                        if portMapping["containerPort"] == 22:
                            containerMappings["ssh"] = containerDef["name"]
                        elif portMapping["containerPort"] == 5900:
                            containerMappings["vnc"] = containerDef["name"]

            data["ssh_container"] = containerMappings.get("ssh")
            data["vnc_container"] = containerMappings.get("vnc")

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
            "subnets": challenge.subnets or "{}",
            "flag_containers": challenge.flag_containers or "{}",
            "security_group": challenge.security_group,
            "launch_type": challenge.launch_type,
            "guide": challenge.guide,
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
        ecs = ECSConfig.query.filter_by(id=1).first()

        data = request.form or request.get_json()
        valid_launch_types = ["ec2", "fargate"]
        if data["launch_type"] not in valid_launch_types:
            raise ValidationError(
                f"launch_type parameter malformed! Expected one of {valid_launch_types}, got `{data['launch_type']}`"
            )
        if "subnets" in data.keys():
            data["subnets"] = json.dumps(data["subnets"])
        if "flag_containers" in data.keys():
            data["flag_containers"] = json.dumps(data["flag_containers"])

        # Discover ssh_container and vnc_container

        ecs_client = boto3.client(
            "ecs",
            ecs.region,
            aws_access_key_id=ecs.aws_access_key_id,
            aws_secret_access_key=ecs.aws_secret_access_key,
            aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
        )
        taskDefinition = data["task_definition"]
        containerDefs = ecs_client.describe_task_definition(
            taskDefinition=taskDefinition
        )["taskDefinition"]["containerDefinitions"]

        containerMappings = {}

        for containerDef in containerDefs:
            if portMappings := containerDef.get("portMappings", []):
                for portMapping in portMappings:
                    if portMapping["containerPort"] == 22:
                        containerMappings["ssh"] = containerDef["name"]
                    elif portMapping["containerPort"] == 5900:
                        containerMappings["vnc"] = containerDef["name"]

        data["ssh_container"] = containerMappings.get("ssh")
        data["vnc_container"] = containerMappings.get("vnc")

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
        challengetracker = ECSChallengeTracker.query.filter_by(
            challenge_id=challenge.id, owner_id=get_current_user().id
        ).first()

        if challengetracker is None:
            return False, "Failed to find challenge task!"

        data = request.form or request.get_json()
        submission = data["submission"].strip()
        flags = Flags.query.filter_by(challenge_id=challenge.id).all()

        for flag in flags:
            if flag.type == "static":
                saved = flag.content.replace("{flag}", f"{{{challengetracker.flag}}}")
                data = flag.data

                if len(saved) != len(submission):
                    return False, "Incorrect"
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

        ecs_task = (
            ECSChallengeTracker.query.filter_by(
                task_definition=challenge.task_definition
            )
            .filter_by(owner_id=user.id)
            .first()
        )
        stop_task(ecs, ecs_task.instance_id)
        ECSChallengeTracker.query.filter_by(instance_id=ecs_task.instance_id).delete()

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

        session = get_current_user()

        # First we'll delete all old docker containers (+2 hours)
        for i in tasks:
            if (
                int(session.id) == int(i.owner_id)
                and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200
            ):
                stop_task(ecs, i.instance_id)
                ECSChallengeTracker.query.filter_by(instance_id=i.instance_id).delete()
                db.session.commit()
        check = (
            ECSChallengeTracker.query.filter_by(owner_id=session.id)
            .filter_by(challenge_id=challenge.id)
            .first()
        )

        # If this container is already created, we don't need another one.
        if (
            check != None
            and not (unix_time(datetime.utcnow()) - int(check.timestamp)) >= 30
        ):
            return abort(403)
        # The exception would be if we are reverting a box. So we'll delete it if it exists and has been around for more than 5 minutes.
        elif check != None:
            stop_task(ecs, check.instance_id)
            ECSChallengeTracker.query.filter_by(owner_id=session.id).filter_by(
                challenge_id=challenge.id
            ).delete()
        # portsbl = get_unavailable_ports(docker)
        flag = "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
        success, result = create_task(
            ecs,
            challenge.task_definition,
            json.loads(challenge.subnets),
            challenge.security_group,
            challenge_id,
            flag,
        )

        if success:
            entry = ECSChallengeTracker(
                owner_id=session.id,
                challenge_id=challenge.id,
                task_definition=challenge.task_definition,
                timestamp=unix_time(datetime.utcnow()),
                revert_time=unix_time(datetime.utcnow()) + 30,
                instance_id=result["tasks"][0]["taskArn"],
                ports="",
                flag=flag,
            )

            db.session.add(entry)
            db.session.commit()
            db.session.close()
            return {"success": True, "data": []}
        else:
            db.session.commit()
            db.session.close()

            return {"success": False, "data": result}


task_status_namespace = Namespace(
    "task_status",
    description="Get the health status (Unknown, Unhealthy, Healthy) of a task.",
)


@task_status_namespace.route("", methods=["GET"])
class TaskStatus(Resource):
    @authed_only
    def get(self):
        ecs = ECSConfig.query.filter_by(id=1).first()

        ecs_client = boto3.client(
            "ecs",
            ecs.region,
            aws_access_key_id=ecs.aws_access_key_id,
            aws_secret_access_key=ecs.aws_secret_access_key,
            aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
        )

        taskInstance = request.args.get("taskInst")

        session = get_current_user()

        challenge_tracker = ECSChallengeTracker.query.filter_by(
            instance_id=taskInstance
        ).first()

        challenge = ECSChallenge.query.filter_by(
            id=challenge_tracker.challenge_id
        ).first()

        if not challenge_tracker:
            if challenge_tracker.owner_id != session.id:
                return {"success": False, "data": []}

        task = ecs_client.describe_tasks(cluster=ecs.cluster, tasks=[taskInstance])[
            "tasks"
        ][0]

        containers = [
            container
            for container in task["containers"]
            if container["name"] in [challenge.ssh_container, challenge.vnc_container]
            and container["healthStatus"] != "HEALTHY"
        ]

        return {
            "success": True,
            "data": {"healthy": not any(containers)},
            "public_ip": get_address_of_task_container(
                ecs,
                taskInstance,
                challenge.entrypoint_container,
            )
            if not ecs.guacamole_address
            else "",
        }


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
            aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
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
            return {"success": False, "data": {}}

        protocol = request.args.get("protocol")

        challenge_id = request.args.get("id")
        challenge = ECSChallenge.query.filter_by(id=challenge_id).first()
        if not is_admin():
            if challenge is None:
                return {"success": False, "data": {}}

        # Get the ECSChallengeTracker for this container

        session = get_current_user()

        if is_admin() and request.args.get("owner"):
            container = ECSChallengeTracker.query.filter_by(
                challenge_id=challenge_id, owner_id=request.args.get("owner")
            ).first()
        else:
            container = ECSChallengeTracker.query.filter_by(
                challenge_id=challenge_id, owner_id=session.id
            ).first()
        if container is None:
            return {"success": False, "data": {}}

        # Identify the IP address of the container

        if protocol == "ssh":
            address = get_address_of_task_container(
                ecs, container.instance_id, challenge.ssh_container
            )
        elif protocol == "vnc":
            address = get_address_of_task_container(
                ecs, container.instance_id, challenge.vnc_container
            )
        else:
            return {"success": False, "data": {}}

        if address is None:
            return {"success": False, "data": {}}

        # Create a ECSHistory entry for the connection

        if ecs.guacamole_address:
            recording_uuid = uuid.uuid4()

            history_entry = ECSHistory(
                user_id=session.id,
                recording_uuid=str(recording_uuid),
                challenge_id=challenge.id,
            )

            db.session.add(history_entry)
            db.session.commit()

        # Create a JWT for this address to hand over to Guacamole

        payload = guacamole.createJSON(
            session.id, address, protocol, history_entry.recording_uuid
        )
        jwt = guacamole.encryptJWT(GUACAMOLE_JSON_SECRET_KEY, json.dumps(payload))

        return {
            "success": True,
            "data": {
                "guacamole_address": ecs.guacamole_address,
                "jwt": jwt.decode("UTF-8"),
                "use_internal_viewer": ecs.guide_enabled,
            },
        }


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
        ecs = ECSConfig.query.first()

        session = get_current_user()
        tracker = ECSChallengeTracker.query.filter_by(owner_id=session.id)
        data = list()
        for i in tracker:
            challenge = ECSChallenge.query.filter_by(id=i.challenge_id).first()

            data.append(
                {
                    "id": i.id,
                    "owner_id": i.owner_id,
                    "challenge_id": i.challenge_id,
                    "timestamp": i.timestamp,
                    "revert_time": i.revert_time,
                    "instance_id": i.instance_id,
                    "guacamole": bool(ecs.guacamole_address),
                    "ssh": bool(challenge.ssh_container),
                    "vnc": bool(challenge.vnc_container),
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
        images = get_task_definitions(ecs)
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
    upgrade(plugin_name="ecs_challenges")

    CHALLENGE_CLASSES["ecs"] = ECSChallengeType
    register_plugin_assets_directory(app, base_path="/plugins/ecs_challenges/assets")
    define_ecs_admin(app)
    define_ecs_status(app)
    define_ecs_history(app)
    define_guacamole_viewer(app)
    CTFd_API_v1.add_namespace(ecs_namespace, "/ecs")
    CTFd_API_v1.add_namespace(ecs_config_namespace, "/ecs_config")
    CTFd_API_v1.add_namespace(task_namespace, "/task")
    CTFd_API_v1.add_namespace(task_status_namespace, "/task_status")
    CTFd_API_v1.add_namespace(container_namespace, "/containers")
    CTFd_API_v1.add_namespace(connect_namespace, "/connect")
    CTFd_API_v1.add_namespace(active_ecs_namespace, "/ecs_status")
    CTFd_API_v1.add_namespace(kill_task, "/nuke")

    # Attempt to perform initial setup of the ECS Config from environment variables

    try:
        ecs = ECSConfig.query.first()

        if ecs is None:
            ecs = ECSConfig()

        if "AWS_ACCESS_KEY_ID" in os.environ.keys():
            ecs.aws_access_key_id = os.environ["AWS_ACCESS_KEY_ID"]

        if "AWS_SECRET_ACCESS_KEY" in os.environ.keys():
            ecs.aws_secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]

        if "AWS_REGION" in os.environ.keys():
            ecs.region = os.environ["AWS_REGION"]

        if "AWS_CLUSTER" in os.environ.keys():
            ecs.cluster = os.environ["AWS_CLUSTER"]

        if "AWS_VPC" in os.environ.keys():
            ecs.active_vpc = os.environ["AWS_VPC"]

        if "AWS_FILTER_TAG" in os.environ.keys():
            ecs.filter_tag = os.environ["AWS_FILTER_TAG"]

        if "GUACAMOLE_JSON_SECRET_KEY" in os.environ.keys():
            ecs.guacamole_json_secret_key = os.environ["GUACAMOLE_JSON_SECRET_KEY"]

        if "GUACAMOLE_ADDRESS" in os.environ.keys():
            ecs.guacamole_address = os.environ["GUACAMOLE_ADDRESS"]

        try:
            if ecs.active_vpc is not None:
                ecs.subnets = json.dumps(get_subnets(ecs, ecs.active_vpc))
                ecs.security_groups = json.dumps(
                    get_security_groups(ecs, ecs.active_vpc)
                )
        except:
            pass

        db.session.add(ecs)
        db.session.commit()
    except:
        # This can fail due to database migrations not yet applied, so we should fail out gracefully
        # (else it breaks the plugin init which occurs before migrations)
        pass
