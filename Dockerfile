FROM golang:1.26-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations

RUN go build -o /out/auth-service ./cmd/api && \
    go build -o /out/migrate ./cmd/migrate

FROM alpine:3.22

WORKDIR /app

RUN addgroup -S app && adduser -S app -G app

COPY --from=build /out/auth-service /usr/local/bin/auth-service
COPY --from=build /out/migrate /usr/local/bin/migrate
COPY --from=build /app/migrations /app/migrations

USER app

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/auth-service"]
