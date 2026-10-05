# Image for the end-to-end tests: a Linux machine with what meshvpn's features touch.
# The meshvpn binary under test is copied into each container at runtime.
FROM debian:stable-slim
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      openssh-server openssh-client sudo iproute2 iputils-ping procps netcat-openbsd \
      python3 iptables conntrack curl ca-certificates tinyproxy tar \
      xterm x11-apps xclip >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd && ssh-keygen -A \
 && useradd -m -s /bin/bash agent
COPY fixtures/torchrun /usr/local/bin/torchrun
COPY fixtures/desktop_client.py /usr/local/bin/desktop_client.py
RUN chmod 755 /usr/local/bin/torchrun /usr/local/bin/desktop_client.py
CMD ["/usr/sbin/sshd", "-D", "-e"]
