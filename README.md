# go-auth-service

Base inicial do Auth Service em Go.

## Documentação

- [Design do serviço](docs/design.md)
- [Plano de implementação da V1](docs/implementation-plan.md)

## Desenvolvimento

1. Copie `.env.example` para `.env`.
2. Ajuste as variáveis conforme seu ambiente.
3. Execute:

```bash
go run ./cmd/api
```

## Endpoints iniciais

- `GET /health`
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
