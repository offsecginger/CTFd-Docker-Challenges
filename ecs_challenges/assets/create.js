CTFd.plugin.run((_CTFd) => {
    const $ = _CTFd.lib.$
    const md = _CTFd.lib.markdown()
    $('a[href="#new-desc-preview"]').on('shown.bs.tab', function (event) {
        if (event.target.hash == '#new-desc-preview') {
            var editor_value = $('#new-desc-editor').val();
            $(event.target.hash).html(
                md.render(editor_value)
            );
        }
    });
    $(document).ready(function () {
        $('[data-toggle="tooltip"]').tooltip();
        $.getJSON("/api/v1/ecs", function (result) {
            $.each(result['data'], function (i, item) {
                if (item.name == 'Error in ECS Config!') {
                    document.ecs_form.taskdefinition_select.disabled = true;
                    $("label[for='TaskDefinition']").text('Task Definition ' + item.name)
                }
                else {
                    $("#taskdefinition_select").append($("<option />").val(item.name).text(item.name));
                }
            });

            fetch_containers();
        });

        $.getJSON("/api/v1/ecs_config", function (result) {
            $.each(result['data']['subnets'], function (i, item) {
                $("#subnet_select").append($("<option />").val(item['value']).text(item['value'] + (item['name'] ? ` [${item['name']}]` : "")));
            });
            $.each(result['data']['security_groups'], function (i, item) {
                $("#security_group_select").append($("<option />").val(item['value']).text(item['value'] + (item['name'] ? ` [${item['name']}]` : "")));
            });
        });
    });
});

function fetch_containers() {
    $.getJSON("/api/v1/containers", { taskDef: $("#taskdefinition_select")[0].value }, function (result) {
        if (result['success']) {
            [...$("#entrypoint_container_select").children()].forEach(child => child.remove());

            $.each(result['data'], function (i, item) {
                $("#entrypoint_container_select").append($("<option />").val(item).text(item))
            });
        }
    });
}
