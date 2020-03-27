FROM archlinux:latest

ARG USER_ID
ARG GROUP_ID

RUN groupadd --gid $GROUP_ID non_root
RUN useradd -s /usr/bin/nologin --uid $USER_ID --gid $GROUP_ID non_root

RUN pacman -Sy binutils fakeroot sudo --noconfirm --needed
RUN echo 'non_root ALL=NOPASSWD: ALL' >> /etc/sudoers
RUN mkdir -p /home/non_root/dnsadblock
WORKDIR /home/non_root/dnsadblock
RUN chown -R non_root:non_root /home/non_root/dnsadblock
RUN chmod 755 /home/non_root/dnsadblock
USER non_root