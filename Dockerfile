FROM python:3

ADD * /

EXPOSE 443

RUN pip3 install aiohttp

CMD ["python3", "MacC2_server.py"]

