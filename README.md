# CTFd ECS Plugin

This is a CTFd plugin that allows you to present challenges that are ran as ECS tasks that users can SSH in to (either via Guacamole or exposed via a public IP) and complete to find a flag. The plugin can run both inside of AWS and outside of it (albeit if you are using guacamole, you need to be running guacamole and guacd inside of ECS).

Initial setup of the plugin can either be done at CTFd startup via environment variables or via the WebUI, the plugin does not need to be able to communicate with guacamole/guacd, so you can run it on its own VPC to more thoroughly isolate your users from the main CTFd service.

The environment variables specific to this plugin available are as follows

* (Optional) `AWS_ACCESS_KEY_ID`: The access key ID to use to connect to AWS
* (Optional) `AWS_SECRET_ACCESS_KEY`: The secret access key to use to connect to AWS
* `AWS_REGION`: The region for the plugin to operate in
* `AWS_CLUSTER`: The cluster (specified using the full ARN) to run tasks in
* `AWS_VPC`: The VPC (specified using the VPC ID) to use for subnets/security groups
* (Optional) `AWS_FILTER_TAG`: The tag key to filter which subnets, security groups and task definitions are shown in the challenge creation options
* (Optional) `GUACAMOLE_JSON_SECRET_KEY`: The secret key to use to encrypt JWTs for Guacamole
* (Optional) `GUACAMOLE_ADDRESS`: The address of the Guacamole server (just the domain)
* (Optional) `GUACAMOLE_SSH_PRIVATE_KEY`: The private key that Guacamole should use for connecting to containers.

Guacamole needs to be configured with the same JSON Secret Key as is given to CTFd.

Whilst the plugin does not need to communicate with Guacamole, the user's browser does, so you need to make sure you configure Guacamole to run on the necessary domain / have the necessary `Access-Control-Allow-Origin` header for the user on the CTFd page for their browser to use the JWT to get a Guacamole Auth Token.

If a Guacamole address is not specified, the plugin will assume you want to operate in public IP mode, and so it will run tasks with the necessary option for them to get a public IP if they're on a subnet that gives them public IPs.

The SSH private key needs to be an RSA key in PEM format.

The plugin does not create any VPCs / subnets / security_groups / etc, it is expected that the user (either through the AWS Console or through a tool like Terraform) creates the necessary resources on AWS for the plugin to operate. 

If you are running within AWS, you do not need to specify the access key or ID via environment variables at all, just ensure that the task role associated with the CTFd task has at least these policies:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ecs:DescribeTaskDefinition",
                "iam:PassRole",
                "ec2:DescribeNetworkInterfaces",
                "ecs:RunTask",
                "ec2:DescribeVpcs",
                "ecs:StopTask",
                "ecs:ListContainerInstances",
                "ec2:DescribeSubnets",
                "ecs:TagResource",
                "ecs:DescribeTasks",
                "ecs:ListTaskDefinitions",
                "ecs:ListClusters"
            ],
            "Resource": "*"
        }
    ]
}
```

Within this repository you will also find a `Dockerfile` that builds CTFd with this plugin and a `docker-compose.yml` that will run CTFd with this plugin alongside MariaDB and Redis. This is the minimum viable configuration to run this plugin locally for testing / development purposes. You will still need to configure AWS to be able to use this plugin with AWS.

## Features
* Players can spawn tasks to attempt challenges, being presented with either a Connect button or the container's public IP once the container is running
* Players can reset a container after 5 minutes
* Tasks older than 2 hours are culled when the user interacts with the site again
* Tasks are stopped once the user has successfully solved the challenge
* Allows specifying the specific container within a task definition that the user should connect in to.
* Allows viewing session recordings when using Guacamole

# Configuring Recordings

The plugin expects that the guacamole address also serves recording files from a `/recordings/` directory. You will need to configure a shared volume between guacd (where it records to `/recordings/`) and a some web server (such as nginx) to serve the contents of that folder at the subdirectory `/recordings/`.

## Creating challenges

Due to the relience on SSH for providing users with access to the containers, and some quirks of Guacamole, this section exists to inform you of how to create challenges for use with this plugin

```Dockerfile
FROM ubuntu

USER root

COPY guac.pub /

RUN mkdir -p /root/.ssh/
RUN cat guac.pub > /root/.ssh/authorized_keys
RUN rm /guac.pub
RUN apt-get -y update && apt-get -y upgrade

RUN apt-get -y install openssh-server

RUN mkdir -p /run/sshd

RUN echo "HostKeyAlgorithms +ssh-rsa" >> /etc/ssh/sshd_config
RUN echo "PubkeyAcceptedAlgorithms +ssh-rsa" >> /etc/ssh/sshd_config

CMD ["sh", "-c", "echo $FLAG_0 > /flag && /usr/sbin/sshd -f /etc/ssh/sshd_config -D -e"]
```

This is the minimum viable Dockerfile for building a challenge. The plugin passes the flags in to the entrypoint container via `$FLAG_x` environment variables. It is the job of the entrypoint of the container to set up other containers within the task as well as placing the flags where they belongs.

Guacd does not communicate with anything stronger than ssh-rsa, so we need to explicitly re-enable it on Ubuntu type images.

#### Credits

* https://github.com/offsecginger (For the original CTFd-Docker-Plugin) (Twitter: @offsec_ginger)
* Jaime Geiger (For Original Plugin assistance) (Twitter: @jgeigerm)
