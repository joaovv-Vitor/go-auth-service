FROM golang:1.26-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN go build -o /out/auth-service ./cmd/api

FROM alpine:3.22

WORKDIR /app

RUN addgroup -S app && adduser -S app -G app

COPY --from=build /out/auth-service /usr/local/bin/auth-service

USER app

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/auth-service"]
