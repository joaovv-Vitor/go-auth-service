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
go run ./cmd/migrate up
go run ./cmd/api
```

Para desfazer apenas a última migration:

```bash
go run ./cmd/migrate down 1
```

### Testes

A suíte unitária não depende de serviços externos:

```bash
go test ./...
```

Os testes de integração criam um schema temporário, aplicam as migrations e
removem o schema ao terminar. Use exclusivamente uma instância PostgreSQL de
teste:

```bash
docker compose up -d postgres
TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable' go test -count=1 ./...
```

Para validar também acessos concorrentes:

```bash
TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable' go test -race -count=1 ./...
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

## Produção

- HTTPS é obrigatório fora do ambiente local e deve ser terminado por um proxy
  reverso ou load balancer confiável.
- `/docs`, `/openapi.*` e `/schemas` ficam desabilitados por padrão quando
  `APP_ENV=production`. Use `API_DOCS_ENABLED=true` somente quando a exposição
  for intencional e protegida.
- Requisições de autenticação aceitam no máximo `HTTP_MAX_BODY_BYTES` bytes
  (padrão: 65536).
- Os custos de senha são configurados por `ARGON2_MEMORY_KIB`,
  `ARGON2_ITERATIONS` e `ARGON2_PARALLELISM`. Valores fora dos limites seguros
  fazem a aplicação falhar no startup.
- CORS permanece desabilitado na V1, adequada a clientes server-to-server. Antes
  de permitir acesso direto de navegadores, configure uma allowlist explícita;
  nunca use origem curinga junto com credenciais.
