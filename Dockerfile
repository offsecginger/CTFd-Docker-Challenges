FROM ctfd/ctfd 

USER root

COPY requirements.txt .
RUN python -m venv /opt/venv
RUN python -m pip install -r ./requirements.txt

COPY ecs_challenges /opt/CTFd/CTFd/plugins/ecs_challenges

USER 1001
