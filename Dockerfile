FROM ctfd/ctfd 

COPY requirements.txt .
RUN python -m pip install -r ./requirements.txt

COPY docker_challenges /opt/CTFd/CTFd/plugins/docker_challenges
