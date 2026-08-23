# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

ARG GO_IMAGE=golang:1.26-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468
ARG RUNTIME_IMAGE=alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

FROM ${GO_IMAGE} AS build

ARG SOURCE_DATE_EPOCH=0

ENV CGO_ENABLED=0

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations

RUN go build -trimpath -buildvcs=false -mod=readonly -ldflags="-buildid=" -o /out/auth-service ./cmd/api && \
    go build -trimpath -buildvcs=false -mod=readonly -ldflags="-buildid=" -o /out/migrate ./cmd/migrate

FROM ${RUNTIME_IMAGE}

ARG SOURCE_DATE_EPOCH=0

WORKDIR /app

RUN addgroup -S app && adduser -S app -G app

COPY --from=build /out/auth-service /usr/local/bin/auth-service
COPY --from=build /out/migrate /usr/local/bin/migrate
COPY --from=build /app/migrations /app/migrations

USER app

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/auth-service"]
