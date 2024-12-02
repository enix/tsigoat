FROM alpine:latest

WORKDIR /app

RUN apk add \
    bash curl \
    bind bind-dnssec-tools \
    python3 pipx ipython \
    go gopls \
    jq yq \
    kubectl helm k9s

ARG USER_ID=1000
ARG GROUP_ID=1000
RUN addgroup -g ${GROUP_ID} shell \
    && adduser -D -s /bin/bash -u ${USER_ID} -G shell shell

USER ${USER_ID}:${GROUP_ID}

ENV PATH="$PATH:/home/shell/.local/bin"
