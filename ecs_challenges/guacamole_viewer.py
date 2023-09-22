from flask import Blueprint, request, render_template, abort
from .models import ECSConfig, ECSChallenge
from CTFd.models import db


def define_guacamole_viewer(app):
    guacamole_viewer = Blueprint(
        "guacamole_viewer",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

    @guacamole_viewer.route("/challenge_player", methods=["GET"])
    def viewer():
        ecs = ECSConfig.query.filter_by(id=1).first()

        if not ecs.guide_enabled:
            abort(403)

        guacamole_access_token = request.args.get("access_token")
        challenge_id = request.args.get("challenge_id")

        if None in [guacamole_access_token, challenge_id]:
            abort(403)

        # Look up challenge

        challenge = ECSChallenge.query.filter_by(id=challenge_id).first()

        if challenge is None:
            abort(403)

        return render_template(
            "guacamole_viewer.html",
            guide=challenge.guide,
            guacamole_address=ecs.guacamole_address,
            guacamole_access_token=guacamole_access_token,
        )

    app.register_blueprint(guacamole_viewer)
