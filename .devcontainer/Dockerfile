FROM ubuntu:18.04

# Install packages
COPY apt_packages.txt /
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y $(cat /apt_packages.txt) && rm -rf /var/lib/apt/lists/*