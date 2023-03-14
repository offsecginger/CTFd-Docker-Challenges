CTFd._internal.challenge.data = undefined

CTFd._internal.challenge.renderer = null;


CTFd._internal.challenge.preRender = function () { }

CTFd._internal.challenge.render = null;

CTFd._internal.challenge.postRender = function () { }


CTFd._internal.challenge.submit = function (preview) {
    var challenge_id = parseInt(CTFd.lib.$('#challenge-id').val())
    var submission = CTFd.lib.$('#challenge-input').val()

    var body = {
        challenge_id: challenge_id,
        submission: submission,
    }
    var params = {}
    if (preview) {
        params['preview'] = true
    }

    return CTFd.api.post_challenge_attempt(params, body).then(function (response) {
        setTimeout(() => get_ecs_status(challenge), 100);
        if (response.status === 429) {
            // User was ratelimited but process response
            return response
        }
        if (response.status === 403) {
            // User is not logged in or CTF is paused.
            return response
        }
        return response
    });
};

function get_ecs_status(challenge) {
    fetch("/api/v1/ecs_status").then(result => result.json()).then(result => {
        if (!result['data'].some((item, i) => {
            if (item.challenge_id == challenge) {
                document.querySelector('#ecs_container').innerHTML = `<pre>ECS Task Information:<br /><div class="mt-2" id="${String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_")}_revert_container"></div><div class="mt-2" id="${String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_")}_connect_to_container"></div>`;
                var countDownDate = new Date(parseInt(item.revert_time) * 1000).getTime();

                let running = false;

                let revert_section = document.querySelector("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_revert_container");
                let connect_section = document.querySelector("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_connect_to_container");

                let status_check_interval = setInterval(function () {
                    var now = new Date().getTime();
                    var distance = countDownDate - now;
                    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                    var seconds = Math.floor((distance % (1000 * 60)) / 1000);
                    if (seconds < 10) {
                        seconds = "0" + seconds
                    }
                    revert_section.innerHTML = 'Able to stop/reset container in ' + minutes + ':' + seconds;
                    if (distance < 0) {
                        clearInterval(status_check_interval);
                        revert_section.innerHTML = `<a onclick="start_container('${item.challenge_id}');" class='btn btn-dark'><small style='color:white;'><i style='margin-right: 5px;' class="fas fa-redo"></i>Reset</small></a>`;
                        revert_section.innerHTML += `<a onclick="stop_container('${item.challenge_id}', '${item.instance_id}');" class='btn btn-dark'><small style='color:white;'><i style='margin-right: 5px;' class="fas fa-stop"></i>Stop</small></a>`;
                    }

                    if (item.guacamole) {
                        if (!running) {
                            fetch(`/api/v1/task_status?${new URLSearchParams({ taskInst: item.instance_id })}`).then(result => result.json()).then(result => {
                                if (result['success']) {
                                    if (result['data']['healthy']) {
                                        running = true;
                                        connect_section.innerHTML = ``;
                                        if (item.ssh)
                                            connect_section.innerHTML += `<a onclick="connect_to_container('${item.challenge_id}', 'ssh');" class='btn btn-dark'><small style='color:white;'>Connect via SSH</small></a>`;
                                        if (item.vnc)
                                            connect_section.innerHTML += `<a onclick="connect_to_container('${item.challenge_id}', 'vnc');" class='btn btn-dark'><small style='color:white;'>Connect via VNC</small></a>`;
                                    } else {
                                        connect_section.innerHTML = `<span>Container Status: ${result['data']['healthy'] ? '' : 'STARTING'}</span>`;
                                    }
                                }
                            });
                        }
                    } else {
                        if (!running) {
                            fetch(`/api/v1/task_status?${new URLSearchParams({ taskInst: item.instance_id })}`).then(result => result.json()).then(result => {
                                if (result['success']) {
                                    if (result['data']['healthy']) {
                                        running = true;
                                        connect_section.innerHTML = `<span>IP: ${result['public_ip']}</small>`;
                                    } else {
                                        connect_section.innerHTML = `<span>Container Status: ${result['data']['healthy'] ? '' : 'STARTING'}</span>`;
                                    }
                                }
                            });
                        }
                    }
                }, 1000);
                return true;
            };
        })) {
            // No existing challenge, inject the start button
            document.querySelector('#ecs_container').innerHTML = `<span>
                <a onclick="start_container('${CTFd.lib.$('#challenge-id').val()}');" class='btn btn-dark'>
                    <small style='color:white;'><i class="fas fa-play"></i> Start ECS Task</small>
                </a>
            </span>`
        }
    });
};

function start_container(challenge) {
    running = false;
    document.querySelector('#ecs_container').innerHTML = '<div class="text-center"><i class="fas fa-circle-notch fa-spin fa-1x"></i></div>';
    fetch(`/api/v1/task?${new URLSearchParams({ 'id': challenge })}`).then(result => result.json()).then(result => {
        if (!result.success) {
            if (result.data[0].indexOf("running") > 0) {
                ezq({ title: "Challenge already running", body: `You already have a challenge already running (${result.data[1]})<br><br>Would you like to stop that challenge and start this one?` }).then(() => {
                    stop_container(result.data[2], result.data[3], false);
                    setTimeout(() => {
                        start_container(challenge);
                    }, 250);
                })
            } else {
                ezal({ title: "Failed to start challenge", body: result.data[0], button: "Dismiss" });
            }
        }

        get_ecs_status(challenge);
    });
}

function stop_container(challenge, task_id, refresh = true) {
    running = false;
    document.querySelector('#ecs_container').innerHTML = '<div class="text-center"><i class="fas fa-circle-notch fa-spin fa-1x"></i></div>';
    fetch(`/api/v1/nuke?${new URLSearchParams({ 'task': task_id })}`).then(result => {
        if (refresh) {
            get_ecs_status(challenge);
        }
    })
}

function connect_to_container(challenge, protocol) {
    fetch(`/api/v1/connect?${new URLSearchParams({ 'id': challenge, 'protocol': protocol })}`).then(result => result.json()).then(result => {
        console.log(result);

        if (result['success']) {
            fetch(`${window.location.protocol}//${result['data'][0]}/guacamole/api/tokens`, { method: 'POST', headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ 'data': result['data'][1] }) }).then(result => result.json()).then(auth => {
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
    '        <button type="button" class="close" data-dismiss="modal" data-bs-dismiss="modal" aria-label="Close">' +
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

function ezq(args) {
    let $ = CTFd.lib.$;
    String.prototype.format = function () { return [...arguments].reduce((acc, c, ci) => acc.replace(`{${ci}}`, c), this) };
    return new Promise((resolve, reject) => {
        var res = modal.format(args.title, args.body);
        var obj = $(res);
        var deny =
            $('<button type="button" class="btn btn-danger" data-dismiss="modal" data-bs-dismiss="modal">No</button>');
        var confirm = $(
            '<button type="button" class="btn btn-primary" data-dismiss="modal" data-bs-dismiss="modal">Yes</button>'
        );

        obj.find(".modal-footer").append(deny);
        obj.find(".modal-footer").append(confirm);

        $("main").append(obj);

        $(obj).on("hidden.bs.modal", function (e) {
            $(this).modal("dispose");
        });

        $(confirm).on("click", function () {
            resolve();
        });

        obj.modal('show');
    });
}

function ezal(args) {
    let $ = CTFd.lib.$;
    String.prototype.format = function () { return [...arguments].reduce((acc, c, ci) => acc.replace(`{${ci}}`, c), this) };

    var res = modal.format(args.title, args.body);
    var obj = $(res);
    var button = '<button type="button" class="btn btn-primary" data-dismiss="modal" data-bs-dismiss="modal">{0}</button>'.format(
        args.button
    );

    obj.find(".modal-footer").append(button);
    $("main").append(obj);

    obj.modal("show");

    $(obj).on("hidden.bs.modal", function (e) {
        $(this).modal("dispose");
    });

    return obj;
}

// Inject the bootstrap Modal plugin if window.Modal is set.
if (window.Modal) {
    let plugin = window.Modal
    let $ = CTFd.lib.$;
    const name = plugin.NAME;
    const JQUERY_NO_CONFLICT = $.fn[name];
    $.fn[name] = plugin.jQueryInterface;
    $.fn[name].Constructor = plugin;
    $.fn[name].noConflict = () => {
        $.fn[name] = JQUERY_NO_CONFLICT;
    };
}

setTimeout(() => get_ecs_status(CTFd.lib.$("#challenge-id").val()), 100);
