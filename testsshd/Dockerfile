# syntax=docker/dockerfile:1

##############################################################################
# A throwaway OpenSSH server, for local testing of hassh-proxy only.
#
# This exists purely so `docker compose watch` has a real SSH backend to
# front without requiring sshd running on the host machine. It is NOT
# hardened and MUST NOT be used for anything beyond local development:
# host keys are generated at build time and baked into the image (so every
# build of this image shares the same keys), and there's a throwaway
# password-auth test user. docker-compose.yml never publishes its port to
# the host -- only the sshproxy service can reach it, over the internal
# Compose network.
##############################################################################

FROM debian:bookworm-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Deliberately unpinned below: this is a disposable test-only fixture (see
# header comment), not a real deliverable, and pinning an exact Debian
# package version here trades a real risk -- that exact version rolling out
# of the bookworm repo snapshot and breaking the build entirely -- for a
# reproducibility benefit that doesn't meaningfully apply to a throwaway
# container that gets rebuilt from scratch on every `docker compose watch`.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sshpass \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && ssh-keygen -A \
    && useradd -m -s /bin/bash testuser \
    && echo 'testuser:testpass' | chpasswd \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22

HEALTHCHECK --interval=20s --timeout=5s --retries=3 \
    CMD sshpass \
            -p "testpass" \
            ssh -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                testuser@localhost id \
        || exit 1

CMD ["/usr/sbin/sshd", "-D", "-e"]
