CTFd.plugin.run((_CTFd) => {
    const $ = _CTFd.lib.$
    const md = _CTFd.lib.markdown()
    $(document).ready(function() {
        $.getJSON("/api/v1/docker", function(result) {
            $.each(result['data'], function(i, item) {
                $("#dockerimage_select").append($("<option />").val(item.name).text(item.name));
            });
            $("#dockerimage_select").val(DOCKER_IMAGE).change();
            $("#docker_image_ports").attr("value", DOCKER_IMAGE_PORTS);
        });
        $("#dockerimage_select").on("change", function() {
            $.getJSON("/api/v1/docker_ports?image=" + this.value, function(result) {
                $("#ports_text").text("Published Ports, Separated With Comma (Allowed Values: " + result["data"].join(", ") + "):");
            });
        });
    });
});