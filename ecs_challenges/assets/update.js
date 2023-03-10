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
                $("#subnets_select").append($("<option />").val(item['value']).text(item['value'] + (item['name'] ? ` [${item['name']}]` : "")));
            });
            ECS_SUBNETS.forEach(v => document.querySelector(`option[value=${v}`).selected = true)

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

$.fn.serializeJSON = function () {
    let target = this[0];

    // First we just recursively get all children of the target

    function getChildren(t) {
        let children = [...t.children];

        let leaves = children.filter(child => child.children.length == 0);
        let nodes = children.filter(child => child.children.length);

        return leaves.concat(nodes.reduce((acc, c) => acc.concat(c.tagName == 'SELECT' ? c : getChildren(c)), []))
    }

    // Get the input and select elements and their values

    return getChildren(target)
        .filter(elem => elem.tagName == 'INPUT' || elem.tagName == "SELECT" || elem.tagName == "TEXTAREA")
        .reduce(
            (acc, c) => (acc[c.name] = c.multiple ? [...c.options]
                .filter(x => x.selected)
                .map(x => x.value) : c.value, acc), {}
        );
}
