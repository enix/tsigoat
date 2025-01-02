FROM --platform=$BUILDPLATFORM golang:1.23.4 AS base
WORKDIR /app

FROM --platform=$BUILDPLATFORM cosmtrek/air:v1.61.5 AS air

FROM base AS dev
ARG USER_ID=1000
ARG GROUP_ID=1000
RUN groupadd -g ${GROUP_ID} air \
    && useradd -l -u ${USER_ID} -g air air \
    && install -d -m 0700 -o air -g air /home/air
USER ${USER_ID}:${GROUP_ID}
COPY --from=air /go/bin/air /go/bin/air
CMD [ "/go/bin/air" ]

FROM base AS build
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download -x
COPY internal internal
COPY pkg pkg
COPY cmd cmd
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG GIT_COMMIT
ARG GIT_STATE
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
RUN go build -v -a -buildvcs=false -o /tsigoat \
    -tags osusergo,netgo \
    -ldflags " \
    -X \"github.com/enix/tsigoat/internal/product.version=${VERSION}\" \
    -X \"github.com/enix/tsigoat/internal/product.gitCommit=${GIT_COMMIT}\" \
    -X \"github.com/enix/tsigoat/internal/product.gitTreeState=${GIT_STATE}\" \
    -X \"github.com/enix/tsigoat/internal/product.buildTime=$(date --iso-8601=seconds)\" \
    " \
    ./cmd/

FROM scratch AS distroless
COPY --from=build --chown=0:0 --chmod=0555 /tsigoat /tsigoat
USER 65534:65534
EXPOSE 5353/udp
EXPOSE 5353/tcp
ENTRYPOINT [ "/tsigoat" ]

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:8bf768ed267ce58d9fd6584c0b17c1c3fd30e9a85c913808627c4fccafb02a69
COPY --from=build --chown=0:0 --chmod=0555 /tsigoat /tsigoat
USER nobody:nobody
EXPOSE 5353/udp
EXPOSE 5353/tcp
ENTRYPOINT [ "/tsigoat" ]
