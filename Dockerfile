FROM python:3

ADD . flowtop

RUN apt update
RUN apt -y dist-upgrade
RUN pip3 install -r flowtop/requirements.txt

ENTRYPOINT python3 flowtop/flowtop.py eth0
