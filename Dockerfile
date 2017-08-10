FROM debian:jessie
RUN apt-get update && \
    apt-get install -y python-paramiko
COPY sftpserver.py /
CMD ["python","/sftpserver.py","-p","22222"]
EXPOSE 22222