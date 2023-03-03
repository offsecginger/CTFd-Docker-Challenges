CTFd._internal.challenge.data = undefined

CTFd._internal.challenge.renderer = null;


CTFd._internal.challenge.preRender = function () { }

CTFd._internal.challenge.render = null;

CTFd._internal.challenge.postRender = function () { }


CTFd._internal.challenge.submit = function (preview) {
    var challenge_id = parseInt(CTFd.lib.$('#challenge-id').val())
    var submission = CTFd.lib.$('#challenge-input').val()

    var body = {
        'challenge_id': challenge_id,
        'submission': submission,
    }
    var params = {}
    if (preview) {
        params['preview'] = true
    }

    return CTFd.api.post_challenge_attempt(params, body).then(function (response) {
        if (response.status === 429) {
            // User was ratelimited but process response
            return response
        }
        if (response.status === 403) {
            // User is not logged in or CTF is paused.
            return response
        }
        return response
    })
};

function get_ecs_status(challenge) {
    fetch("/api/v1/ecs_status").then(result => result.json()).then(result => {
        result['data'].forEach((item, i) => {
            if (item.challenge_id == challenge) {
                var ports = String(item.ports).split(',');
                var data = '';
                document.querySelector('#ecs_container').innerHTML = '<pre>ECS Task Information:<br />' + data + '<div class="mt-2" id="' + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + '_revert_container"></div>' + '<div class="mt-2" id="' + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + '_connect_to_container"></div>';
                var countDownDate = new Date(parseInt(item.revert_time) * 1000).getTime();

                let running = false;

                var x = setInterval(function () {
                    var now = new Date().getTime();
                    var distance = countDownDate - now;
                    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                    var seconds = Math.floor((distance % (1000 * 60)) / 1000);
                    if (seconds < 10) {
                        seconds = "0" + seconds
                    }
                    document.querySelector("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_revert_container").innerHTML = 'Able to reset container in ' + minutes + ':' + seconds;
                    if (distance < 0) {
                        clearInterval(x);
                        document.querySelector("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_revert_container").innerHTML = '<a onclick="start_container(\'' + item.challenge_id + '\');" class=\'btn btn-dark\'><small style=\'color:white;\'><i class="fas fa-redo"></i> Revert</small></a>';
                    }

                    if (item.guacamole) {
                        if (!running) {
                            fetch(`/api/v1/task_status?${new URLSearchParams({ taskInst: item.instance_id })}`).then(result => result.json()).then(result => {
                                if (result['success']) {
                                    if (result['data'] == 'RUNNING') {
                                        running = true;
                                        document.querySelector("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_connect_to_container").innerHTML = '<a onclick="connect_to_container(\'' + item.challenge_id + '\');" class=\'btn btn-dark\'><small style=\'color:white;\'>Connect</small></a>';
                                    } else {
                                        document.querySelector("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_connect_to_container").innerHTML = `<span>Container Status: ${result['data']}</span>`;
                                    }
                                }
                            });
                        }
                    } else {
                        if (!running) {
                            fetch(`/api/v1/task_status?${new URLSearchParams({ taskInst: item.instance_id })}`).then(result => result.json()).then(result => {
                                if (result['success']) {
                                    if (result['data'] == 'RUNNING') {
                                        running = true;
                                        document.querySelector("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_connect_to_container").innerHTML = `<span>IP: ${result['public_ip']}</small>`;
                                    } else {
                                        document.querySelector("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_connect_to_container").innerHTML = `<span>Container Status: ${result['data']}</span>`;
                                    }
                                }
                            });
                        }
                    }
                }, 1000);
                return false;
            };
        });
    });
};

function start_container(challenge) {
    running = false;
    document.querySelector('#ecs_container').innerHTML = '<div class="text-center"><i class="fas fa-circle-notch fa-spin fa-1x"></i></div>';
    fetch(`/api/v1/task?${new URLSearchParams({ 'id': challenge })}`).then(result => {
        if (!result.ok) {
            /*ezal({
                title: "Attention!",
                body: "You can only revert a container once per 5 minutes! Please be patient.",
                button: "Got it!"
            });*/
        }

        get_ecs_status(challenge);
    })
}

function connect_to_container(challenge) {
    fetch(`/api/v1/connect?${new URLSearchParams({ 'id': challenge })}`).then(result => result.json()).then(result => {
        console.log(result);

        if (result['success']) {
            fetch(`${window.location.protocol}//${result['data'][0]}/guacamole/api/tokens`, { method: 'POST', post: JSON.stringify({ 'data': result['data'][1] }) }).then(result => result.json()).then(auth => {
                window.open(`${window.location.protocol}//${result['data'][0]}/guacamole/?token=${auth['authToken']}`, "_blank");
            });
        } else {
            ezal({
                title: "Attention!",
                body: "Failed to connect to the container. Please try again shortly.",
                button: "Got it!"
            });
        }
    });
}

var modal =
    '<div class="modal fade" tabindex="-1" role="dialog">' +
    '  <div class="modal-dialog" role="document">' +
    '    <div class="modal-content">' +
    '      <div class="modal-header">' +
    '        <h5 class="modal-title">{0}</h5>' +
    '        <button type="button" class="close" data-dismiss="modal" aria-label="Close">' +
    '          <span aria-hidden="true">&times;</span>' +
    "        </button>" +
    "      </div>" +
    '      <div class="modal-body">' +
    "        <p>{1}</p>" +
    "      </div>" +
    '      <div class="modal-footer">' +
    "      </div>" +
    "    </div>" +
    "  </div>" +
    "</div>";

function ezal(args) {
    var res = modal.format(args.title, args.body);
    var temp = document.createElement('div');
    temp.innerHTML = res;
    var obj = res.firstChild;
    var button = '<button type="button" class="btn btn-primary" data-dismiss="modal">{0}</button>'.format(
        args.button
    );
    obj.find(".modal-footer").append(button);
    document.querySelector("main").append(obj);

    obj.modal("show");

    obj.on("hidden.bs.modal", function (e) {
        $(this).modal("dispose");
    });

    return obj;
}
