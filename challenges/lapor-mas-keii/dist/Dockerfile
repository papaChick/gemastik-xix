FROM ubuntu:22.04

ARG PASSWORD
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc make libc6-dev \
        openssh-server nano vim-tiny curl procps ca-certificates util-linux && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/ctfuser -s /bin/bash ctfuser && echo ctfuser:${PASSWORD} | chpasswd && \
    useradd -r -M -U -s /usr/sbin/nologin svc

WORKDIR /app
COPY src/ /app/src/
COPY guard/ /app/guard/
RUN chown -R ctfuser:ctfuser /app/src && chmod -R g+rX /app/src && \
    chown root:root /app/guard/detector.bin && chmod 444 /app/guard/detector.bin && \
    chown ctfuser:ctfuser /app/guard/guard.conf && chmod 644 /app/guard/guard.conf

RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "AllowUsers ctfuser" >> /etc/ssh/sshd_config && \
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config && \
    ssh-keygen -A && mkdir -p /run/sshd && chmod 755 /run/sshd

RUN touch /flag.txt && chmod 644 /flag.txt

COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 9000 22
CMD ["/app/start.sh"]
