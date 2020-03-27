FROM archlinux:latest

RUN pacman -Sy binutils fakeroot sudo --noconfirm --needed
RUN useradd non_root && mkdir /home/non_root && chown -R non_root:non_root /home/non_root
RUN echo 'non_root ALL=NOPASSWD: ALL' >> /etc/sudoers
RUN mkdir -p /home/non_root/dnsadblock
WORKDIR /home/non_root/dnsadblock
RUN chown -R non_root:non_root /home/non_root/dnsadblock
RUN chmod 755 /home/non_root/dnsadblock
USER non_root