CTFd.plugin.run((_CTFd) => {
    const $ = _CTFd.lib.$
    const md = _CTFd.lib.markdown()
    $(document).ready(function () {
        $.getJSON("/api/v1/ecs", function (result) {
            $.each(result['data'], function (i, item) {
                $("#taskdefinition_select").append($("<option />").val(item.name).text(item.name));
            });
            $("#taskdefinition_select").val(ECS_TASK_DEFINITION).change();
        });

        fetch_containers();

        $.getJSON("/api/v1/ecs_config", function (result) {
            $.each(result['data']['subnets'], function (i, item) {
                $("#subnet_select").append($("<option />").val(item['value']).text(item['value'] + (item['name'] ? ` [${item['name']}]` : "")));
            });
            $("#subnet_select").val(ECS_SUBNET).change();
            $.each(result['data']['security_groups'], function (i, item) {
                $("#security_group_select").append($("<option />").val(item['value']).text(item['value'] + (item['name'] ? ` [${item['name']}]` : "")));
            });
            $("#security_group_select").val(ECS_SECURITY_GROUP).change();

            $("#launch_type_select").val(ECS_LAUNCH_TYPE).change();
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

            $("#entrypoint_container_select").val(ECS_ENTRYPOINT_CONTAINER).change();
        }
    });
}
