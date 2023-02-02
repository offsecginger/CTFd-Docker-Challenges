CTFd.plugin.run((_CTFd) => {
    const $ = _CTFd.lib.$
    const md = _CTFd.lib.markdown()
    $(document).ready(function () {
        $.getJSON("/api/v1/docker", function (result) {
            $.each(result['data'], function (i, item) {
                $("#dockerimage_select").append($("<option />").val(item.name).text(item.name));
            });
            $("#dockerimage_select").val(DOCKER_IMAGE).change();
        });

        $.getJSON("/api/v1/docker_config", function (result) {
            $.each(result['data']['subnets'], function (i, item) {
                $("#subnet_select").append($("<option />").val(item).text(item));
            });
            $.each(result['data']['security_groups'], function (i, item) {
                $("#security_group_select").append($("<option />").val(item).text(item));
            });
        });
    });
});
