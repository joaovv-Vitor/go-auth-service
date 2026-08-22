# go-auth-service

Base inicial do Auth Service em Go.

## Documentação

- [Design do serviço](docs/design.md)
- [Plano de implementação da V1](docs/implementation-plan.md)

## Desenvolvimento

1. Copie `.env.example` para `.env`.
2. Gere as chaves RSA de desenvolvimento:

```bash
openssl genrsa -out certs/jwt.private.pem 2048
openssl rsa -in certs/jwt.private.pem -pubout -out certs/jwt.public.pem
```

3. Ajuste as variáveis conforme seu ambiente.
4. Execute:

```bash
go run ./cmd/api
```

## Endpoints iniciais

- `GET /health`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET /api/v1/users/me`
- `GET /.well-known/jwks.json`
- `GET /openapi.json` — especificação OpenAPI gerada pelo Huma
- `GET /docs` — documentação interativa
- `GET /schemas` — schemas JSON da API

O roteamento é feito pelo Chi, enquanto o Huma registra as operações, valida
entradas/saídas e gera a especificação OpenAPI.

## Ambiente local com Docker

```bash
docker compose up --build
```

As chaves são montadas no container somente para desenvolvimento e não devem
ser versionadas ou usadas em produção.
