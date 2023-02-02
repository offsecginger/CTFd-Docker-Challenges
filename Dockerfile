FROM ctfd/ctfd 

COPY requirements.txt .
RUN python -m pip install -r ./requirements.txt

COPY ecs_challenges /opt/CTFd/CTFd/plugins/ecs_challenges
