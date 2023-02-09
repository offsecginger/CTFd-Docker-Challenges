CTFd._internal.challenge.data = undefined

CTFd._internal.challenge.renderer = CTFd.lib.markdown();


CTFd._internal.challenge.preRender = function () { }

CTFd._internal.challenge.render = function (markdown) {

    return CTFd._internal.challenge.renderer.render(markdown)
}


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
    $.get("/api/v1/ecs_status", function (result) {
        $.each(result['data'], function (i, item) {
            if (item.challenge_id == challenge) {
                var ports = String(item.ports).split(',');
                var data = '';
                $.each(ports, function (x, port) {
                    port = String(port)
                    //data = data + 'Host: ' + item.host + ' Port: ' + port + '<br />';
                })
                $('#ecs_container').html('<pre>ECS Task Information:<br />' + data + '<div class="mt-2" id="' + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + '_revert_container"></div>' + '<div class="mt-2" id="' + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + '_connect_to_container"></div>');
                var countDownDate = new Date(parseInt(item.revert_time) * 1000).getTime();
                var x = setInterval(function () {
                    var now = new Date().getTime();
                    var distance = countDownDate - now;
                    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                    var seconds = Math.floor((distance % (1000 * 60)) / 1000);
                    if (seconds < 10) {
                        seconds = "0" + seconds
                    }
                    $("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_revert_container").html('Next Revert Available in ' + minutes + ':' + seconds);
                    if (distance < 0) {
                        clearInterval(x);
                        $("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_revert_container").html('<a onclick="start_container(\'' + item.challenge_id + '\');" class=\'btn btn-dark\'><small style=\'color:white;\'><i class="fas fa-redo"></i> Revert</small></a>');
                    }

                    $("#" + String(item.instance_id).replaceAll(":", "_").replaceAll("/", "_") + "_connect_to_container").html('<a onclick="connect_to_container(\'' + item.challenge_id + '\');" class=\'btn btn-dark\'><small style=\'color:white;\'>Connect</small></a>');
                }, 1000);
                return false;
            };
        });
    });
};

function start_container(challenge) {
    $('#ecs_container').html('<div class="text-center"><i class="fas fa-circle-notch fa-spin fa-1x"></i></div>');
    $.get("/api/v1/task", { 'id': challenge }, function (result) {
        get_ecs_status(challenge);
    })
        .fail(function (jqxhr, settings, ex) {
            ezal({
                title: "Attention!",
                body: "You can only revert a container once per 5 minutes! Please be patient.",
                button: "Got it!"
            });
            $(get_ecs_status(challenge));
        });
}

function connect_to_container(challenge) {
    $.getJSON("/api/v1/connect", { 'id': challenge }, function (result) {
        console.log(result);

        if (result['success']) {
            $.post(`http://${result['data'][0]}/guacamole/api/tokens`, { 'data': result['data'][1] }, function (auth) {
                window.open(`http://${result['data'][0]}/guacamole/?token=${auth['authToken']}`, "_blank");
            }, "json");
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
    var obj = $(res);
    var button = '<button type="button" class="btn btn-primary" data-dismiss="modal">{0}</button>'.format(
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
