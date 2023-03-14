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
                    $("#taskdefinition_select").append($("<option />").val(item.name).text(item.name.split('/')[1]));
                }
            });

            fetch_containers();
        });

        $.getJSON("/api/v1/ecs_config", function (result) {
            $.each(result['data']['subnets'], function (i, item) {
                $("#subnets_select").append($("<option />").val(item['value']).text(item['value'] + (item['name'] ? ` [${item['name']}]` : "")));
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
            [...$("#flag_containers_select").children()].forEach(child => child.remove());
            $.each(result['data'], function (i, item) {
                $("#flag_containers_select").append($("<option />").val(item).text(item))
            });
        }
    });
}

$.fn.serializeJSON = function () {
    let target = this[0];

    // First we recursively get all children of the target

    function getChildren(t) {
        let children = [...t.children];

        let leaves = children.filter(child => child.children.length == 0);
        let nodes = children.filter(child => child.children.length);

        return leaves.concat(nodes.reduce((acc, c) => acc.concat(c.tagName == 'SELECT' ? c : getChildren(c)), []))
    }

    // Get the input, select and textarea elements and their values

    return getChildren(target)
        .filter(elem => elem.name && (elem.tagName == 'INPUT' || elem.tagName == "SELECT" || elem.tagName == "TEXTAREA"))
        .reduce(
            (acc, c) => (acc[c.name] = c.multiple && c.tagName == 'SELECT' ? [...c.options]
                .filter(x => x.selected)
                .map(x => x.value) : c.value, acc), {}
        );
}
