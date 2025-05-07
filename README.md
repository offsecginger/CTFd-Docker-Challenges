# CTFd Docker Plugin
This plugin for CTFd will allow your competing teams/users to start dockerized images for presented challenges. It adds a challenge type "docker" that can be assigned a specific docker image/tag. A few notable requirements:

* Docker Config must be set first. You can access this via `/admin/docker_config`. Currently supported config is pure http (no encryption/authentication) or full TLS with client certificate validation. Configuration information for TLS can be found here: https://docs.docker.com/engine/security/https/
* This plugin is written so that challenges are stored by tags. For example, StormCTF stores all docker challenges for InfoSeCon2019 in the `stormctf/infosecon2019` repository. A challenge example would be `stormctf/infosecon2019:arbit`. This is how you would call the challenge when creating a new challenge.


## Important Notes

* It is unknown if using the same tag twice will cause issues. This plugin was written to avoid this issue, but it has not been fully tested.
* As with all plugins, please security test your Scoreboard before launching the CTF. This plugin has been tested and vetted in the StormCTF environment, but yours may vary.
* This version of the plugin is modified for CTFd version 3.7. Tested on Version 3.7.7

*Requires flask_wtf*
`pip install flask_wtf`

## Features

* Allows players to spawn their own docker container for docker challenges.
* 5 minute revert timer.
* 2 hour stale container nuke.
* Status panel for Admins to manage docker containers currently active.
* Support for client side validation TLS docker api connections (HIGHLY RECOMMENDED).
* Docker container kill on solve.
* (Mostly) Seamless integration with CTFd.
* **Untested**: _Should_ be able to seamlessly integrate with other challenge types.

## Installation / Configuration

* Drop the folder `docker_challenges` into `CTFd/CTFd/plugins` (Exactly this name).
* Restart CTFd.
* Navigate to `/admin/docker_config`. Add your configuration information. Click Submit.
* Add your required repositories for this CTF. You can select multiple by holding CTRL when clicking. Click Submit.
* Click Challenges, Select `docker` for challenge type. Create a challenge as normal, but select the correct docker tag for this challenge.
* Double check the front end shows "Start Docker Instance" on the challenge.
* Confirm users are able to start/revert and access docker challenges.
* For web challenges, configure http://host:port in the connection field, this is changed automagically when the docker is started
* Host an awesome CTF!

### Update: 20210206
Works with 3.2.1

* Updated the entire plugin to work with the new CTFd.

### Update: 20250507
Works with 3.7.7 and added features:
* Proper check for duplicate containers, a user can run only one at a time.
* Added stop container function.
* Enhanced the Status panel for Admins.
* Some GUI enhancements
* Improved error handling

#### Credits

* https://github.com/offsecginger (Twitter: @offsec_ginger)
* Jaime Geiger (For Original Plugin assistance) (Twitter: @jgeigerm)
