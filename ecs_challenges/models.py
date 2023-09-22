from CTFd.models import db, Challenges


class ECSConfig(db.Model):
    """
    ECS Config Model. This model stores the config for AWS connections and ECS cluster config.
    """

    id = db.Column(db.Integer, primary_key=True)
    task_definitions = db.Column("repositories", db.Text)

    active_vpc = db.Column("active_vpc", db.String(64), index=True)

    aws_access_key_id = db.Column("aws_access_key_id", db.String(20))
    aws_secret_access_key = db.Column("aws_secret_access_key", db.String(40))
    cluster = db.Column("cluster", db.String(128))

    subnets = db.Column("subnets", db.Text)
    security_groups = db.Column("security_groups", db.Text)

    region = db.Column("region", db.String(32))

    guacamole_address = db.Column("guacamole_address", db.String(128))

    guacamole_json_secret_key = db.Column("guacamole_json_secret_key", db.String(128))

    filter_tag = db.Column("filter_tag", db.String(128))

    guide_enabled = db.Column("guide_enabled", db.Boolean())


class ECSChallengeTracker(db.Model):
    """
    ECS Task Tracker. This model stores the users/teams active ECS tasks.
    """

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column("owner_id", db.String(64), index=True)
    task_definition = db.Column("task_definition", db.String(128), index=True)
    challenge_id = db.Column("challenge_id", db.Integer, index=True)
    timestamp = db.Column("timestamp", db.Integer, index=True)
    revert_time = db.Column("revert_time", db.Integer, index=True)
    instance_id = db.Column("instance_id", db.String(128), index=True)
    ports = db.Column("ports", db.String(128), index=True)
    host = db.Column("host", db.String(128), index=True)
    flag = db.Column("flag", db.String(128), index=True)


class ECSChallenge(Challenges):
    __mapper_args__ = {"polymorphic_identity": "ecs"}
    id = db.Column(None, db.ForeignKey("challenges.id"), primary_key=True)
    task_definition = db.Column(db.String(128), index=True)
    subnets = db.Column(db.Text)
    security_group = db.Column(db.String(128), index=True)
    launch_type = db.Column(db.String(32))

    ssh_container = db.Column(
        db.String(128)
    )  # These could end up being the same but we'll track them separately.
    vnc_container = db.Column(db.String(128))
    flag_containers = db.Column(db.Text)

    guide = db.Column(db.Text, default="")


class ECSHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.Integer)
    recording_uuid = db.Column(db.Text)
    challenge_id = db.Column(db.Integer)
