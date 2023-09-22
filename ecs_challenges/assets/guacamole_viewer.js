function openguide() {
    document.querySelector("#guide_open").style.display = 'none';
    document.querySelector("#guide").style.display = 'block';
}

function closeguide() {
    document.querySelector("#guide_open").style.display = '';
    document.querySelector("#guide").style.display = '';
}

let initX, initW;

let client;
let guide_focused = false;
document.addEventListener("DOMContentLoaded", function () {
    let getParams = window.location.search.substring(1).split("&").map(x => x.split("=")).reduce((acc, x) => (acc[x[0]] = x[1], acc), {});

    let guide = document.querySelector("#guide");

    document.querySelector('#resize_bar').addEventListener('mousedown', function (e) {
        e.preventDefault();
        initX = e.clientX;
        initW = parseInt(window.getComputedStyle(guide).width);

        function drag(e) {
            e.preventDefault();
            e.stopImmediatePropagation();
            let delta = e.clientX - initX;
            guide.style.width = `${initW + delta}px`;
        }

        function stopdrag(e) {
            document.documentElement.removeEventListener('mousemove', drag, false);
            document.documentElement.removeEventListener('mouseup', stopdrag, false);
        }

        document.documentElement.addEventListener('mousemove', drag, false);
        document.documentElement.addEventListener('mouseup', stopdrag, false);
    }, false);

    document.querySelectorAll("#guide img").forEach(img => {
        img.addEventListener("click", () => {
            // TODO: Make it such that clicking an image brings up a larger centred instance of it.

            document.querySelector("#full_image_container>img").setAttribute("src", img.getAttribute("src"));
            document.querySelector("#full_image").style.display = "flex";

            rescale();
        });
    });

    document.querySelector("#full_image_close_button").addEventListener("click", () => {
        document.querySelector("#full_image").style.display = "";
    });

    document.querySelector("#full_image").addEventListener("click", () => {
        document.querySelector("#full_image").style.display = "";
    });

    document.querySelectorAll("code").forEach(code => {
        code.addEventListener("click", e => {
            // Copy code when clicked
            navigator.clipboard.writeText(code.innerText);

            document.querySelector("#guide_close").innerHTML = "Copied!";
            setTimeout(() => document.querySelector("#guide_close").innerHTML = "Close Guide", 1000);
        });

        code.innerHTML = code.innerHTML.replace("\n", "").replaceAll("\n", "<br>");
    });

    let websocket_url = `wss://${decodeURIComponent(GUACAMOLE_ADDRESS)}/guacamole/websocket-tunnel`;

    let tunnel = new Guacamole.WebSocketTunnel(`${websocket_url}?token=${getParams['access_token']}&GUAC_ID=1&GUAC_DATA_SOURCE=json&GUAC_TYPE=c&GUAC_TIMEZONE=Europe%2FLondon`);
    client = new Guacamole.Client(tunnel);
    let element = client.getDisplay().getElement();
    document.querySelector("#client").appendChild(element);
    client.connect();

    let mouse = new Guacamole.Mouse(element);

    mouse.onEach(['mousedown', 'mousemove', 'mouseup'], e => client.sendMouseState(e.state, true));
    mouse.on('mouseout', () => client.getDisplay().showCursor(false));

    let keyboard = new Guacamole.Keyboard(document);

    keyboard.onkeydown = (keysym) => client.sendKeyEvent(1, keysym);
    keyboard.onkeyup = (keysym) => client.sendKeyEvent(0, keysym);

    client.onclipboard = (inputStream, mimetype) => {
        if (!mimetype.startsWith("text/"))
            return;

        let reader = new Guacamole.StringReader(inputStream);

        let text = "";
        reader.ontext = v => text += v;
        reader.onend = () => navigator.clipboard.writeText(text);
    }

    let stream_indices = new Guacamole.IntegerPool();

    let resyncclipboard = () => {
        navigator.clipboard.readText().then(clipboardText => {
            let index = stream_indices.next();
            let outputStream = new Guacamole.OutputStream(client, index);
            tunnel.sendMessage("clipboard", index, "text/plain");
            let writer = new Guacamole.StringWriter(outputStream);

            writer.sendText(clipboardText);
            writer.sendEnd();
        }).catch(() => { });
    };

    window.addEventListener("load", resyncclipboard);
    window.addEventListener("focus", resyncclipboard);
    document.querySelector("#client").addEventListener("mouseenter", resyncclipboard);

    let rescale = () => {
        let disp = client.getDisplay();
        let doc = document.documentElement;

        let dispAR = disp.getWidth() / disp.getHeight();
        let docAR = doc.clientWidth / doc.clientHeight;

        if (docAR > dispAR) {
            // Document wider than display, scale vertically
            disp.scale(doc.clientHeight / disp.getHeight());
        } else {
            // Document taller than display, scale horizontally
            disp.scale(doc.clientWidth / disp.getWidth());
        }
        let image = document.querySelector("#full_image_container>img");
        let imageAR = (image.naturalWidth / image.naturalHeight);

        let desired_height = (doc.clientWidth * 0.7) / imageAR;
        let desired_width = (doc.clientHeight * 0.7) * imageAR;

        if (desired_height > doc.clientHeight * 0.7 && desired_width < doc.clientWidth * 0.7) {
            image.style.width = 'auto';
            image.style.height = `${doc.clientHeight * 0.7}px`;
        }

        if (desired_width > doc.clientWidth * 0.7 && desired_height < doc.clientHeight * 0.7) {
            image.style.width = `${doc.clientWidth * 0.7}px`;
            image.style.height = 'auto';
        }
    };

    window.onresize = rescale;
    client.getDisplay().onresize = rescale;
});
