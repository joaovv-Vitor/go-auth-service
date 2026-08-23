# Auth Service — Plano de Implementação da V1

Este plano transforma o [design](./design.md) em uma sequência executável de
entregas. O objetivo da V1 é permitir cadastro, login, uso de JWT em outros
serviços, renovação com rotação de refresh token e logout, mantendo o serviço
pequeno e independente.

## 1. Estado atual

O repositório já possui:

- módulo Go e entrypoint em `cmd/api`;
- carregamento inicial de configurações por variáveis de ambiente;
- servidor HTTP com encerramento gracioso;
- Chi como roteador e Huma como camada de API/OpenAPI;
- endpoints provisórios de health check e JWKS;
- Dockerfile, Compose e PostgreSQL local;
- documentação OpenAPI em `/openapi.json`, `/openapi.yaml` e `/docs`.

Ainda não existem conexão com o banco, migrations, domínio de usuários,
Argon2id, emissão/validação de JWT, persistência de refresh tokens ou os fluxos
de autenticação.

## 2. Decisões de implementação

Estas decisões completam pontos que o design deixa em aberto sem alterar o
escopo da V1.

### 2.1 Organização interna

Usar uma separação simples por domínio:

```text
cmd/api                    composição e ciclo de vida do processo
internal/config            leitura e validação da configuração
internal/database          pool pgx e utilitários transacionais
internal/platform/httpx    erros, middlewares e convenções HTTP
internal/password          Argon2id
internal/token             JWT, chaves, JWKS e refresh tokens
internal/user              modelo e persistência de usuários
internal/auth              casos de uso e endpoints de autenticação
migrations                 migrations SQL versionadas
```

Handlers dependem de services; services dependem de repositories e serviços
criptográficos. Tipos do Huma ficam na camada HTTP e não entram nos modelos de
banco.

### 2.2 Huma + Chi + Swagger/OpenAPI

- Chi tratará roteamento e middlewares de transporte: request ID, IP real,
  recovery, logging e CORS quando habilitado.
- Huma registrará operações, validará entradas e saídas, produzirá erros HTTP e
  gerará OpenAPI.
- A configuração OpenAPI declarará `bearerAuth` como HTTP Bearer com formato
  JWT.
- Rotas protegidas declararão o security scheme na própria operação Huma.
- `/docs` será a interface interativa padrão; `/openapi.json` será o contrato
  consumível pelo Swagger UI e por geradores de clientes.
- A especificação OpenAPI deverá ser testada para garantir que todas as rotas da
  V1 e o esquema Bearer estejam documentados.

### 2.3 Usuários e roles

- O banco manterá uma única coluna `role` na V1, limitada a `USER` e `ADMIN`.
- O cadastro público sempre criará `USER`; não aceitará role no payload.
- A API e o JWT continuarão expondo `roles` como lista, inicialmente com um
  único item. Isso preserva o contrato para uma evolução futura.
- E-mails serão validados, terão espaços externos removidos e serão convertidos
  para minúsculas antes da persistência.
- A restrição UNIQUE do PostgreSQL será a garantia final contra duplicidade.

### 2.4 Senhas

- Usar `golang.org/x/crypto/argon2` com Argon2id.
- Persistir o hash completo em formato PHC, contendo algoritmo, versão,
  parâmetros, salt e hash.
- Gerar salt aleatório para cada senha.
- Comparar hashes em tempo constante.
- Parâmetros de memória, iterações e paralelismo serão configuráveis e validados
  na inicialização.
- Definir uma política mínima de senha antes do endpoint de cadastro; sugestão
  inicial: entre 12 e 128 bytes, sem regras artificiais de composição.

### 2.5 Access token

- JWT assinado com RS256 e chave privada carregada de arquivo PEM.
- Header com `alg`, `typ` e `kid`.
- Claims mínimas: `sub`, `email`, `roles`, `iss`, `iat` e `exp`.
- TTL padrão de 15 minutos.
- Validação exige assinatura, algoritmo RS256, issuer e timestamps válidos.
- A chave pública será convertida para JWK e publicada em
  `/.well-known/jwks.json` com o mesmo `kid` usado no token.
- A chave privada nunca será incluída em imagem, resposta, log ou repositório.

Antes da implementação, escolher e fixar uma única biblioteca para JWT e JWK.
Dar preferência a uma biblioteca que trate ambos para evitar código manual de
serialização do JWKS.

### 2.6 Refresh token e sessão

O modelo mínimo do design precisa de campos adicionais para permitir rotação
atômica e detectar reutilização. A tabela deverá possuir:

```text
refresh_tokens
├── id                    uuid PK
├── family_id             uuid NOT NULL
├── parent_token_id       uuid NULL FK
├── replaced_by_token_id  uuid NULL FK
├── user_id               uuid NOT NULL FK
├── token_hash            bytea NOT NULL
├── expires_at            timestamptz NOT NULL
├── used_at               timestamptz NULL
├── revoked_at            timestamptz NULL
└── created_at            timestamptz NOT NULL
```

- O token entregue ao cliente será opaco, aleatório e terá alta entropia.
- O identificador poderá ser usado como seletor; somente o hash da parte secreta
  será persistido.
- Como o segredo já é aleatório e de alta entropia, usar SHA-256/HMAC-SHA-256
  para armazenamento e comparação, não Argon2id.
- Uma família representa uma sessão lógica e permite revogar toda a cadeia.
- Rotação ocorrerá em transação com bloqueio da linha (`SELECT ... FOR UPDATE`).
- A transação marcará o token anterior como usado, criará o próximo token e
  ligará ambos; ou falhará sem deixar estado parcial.
- Reutilização de um token já usado revogará toda a família.
- Logout revogará a família associada ao refresh token informado.
- TTL padrão de 7 dias; decidir no início se cada rotação renova a janela ou
  preserva uma expiração absoluta. Para a V1, preferir expiração absoluta da
  família para impedir sessões indefinidas.

### 2.7 Erros e privacidade

Adotar um modelo único para respostas de erro:

```json
{
  "error": "invalid_credentials",
  "message": "E-mail ou senha inválidos.",
  "details": []
}
```

- Customizar o modelo de erro do Huma para incluir o código estável em `error`.
- Erros de validação podem incluir detalhes por campo sem revelar valores
  sensíveis.
- Login de usuário inexistente e senha incorreta retornam a mesma resposta e o
  mesmo status.
- Erros internos são logados com contexto e retornam mensagem genérica.
- Senhas, tokens, hashes e conteúdo do header `Authorization` nunca entram em
  logs ou erros.

## 3. Dependências previstas

Adicionar dependências somente na fase em que forem usadas:

| Finalidade | Escolha |
| --- | --- |
| API e OpenAPI | Huma v2 |
| Router | Chi v5 |
| PostgreSQL | `pgx/v5` e `pgxpool` |
| Argon2id | `golang.org/x/crypto/argon2` |
| UUID | biblioteca UUID pequena ou geração pelo PostgreSQL |
| JWT/JWK | uma biblioteca única com suporte a RS256 e JWKS |
| Migrations | migrations SQL com ferramenta CLI fixada no projeto |
| Testes de integração | PostgreSQL real via Compose ou Testcontainers |

Logging utilizará `log/slog` da biblioteca padrão. Evitar framework de DI,
ORM, Redis e message broker na V1.

## 4. Modelo de banco planejado

### 4.1 `users`

```sql
id             uuid primary key
name           varchar(120) not null
email          varchar(320) not null unique
password_hash  text not null
role           varchar(20) not null default 'USER'
created_at     timestamptz not null
updated_at     timestamptz not null
```

Restrições:

- `role IN ('USER', 'ADMIN')`;
- e-mail armazenado normalizado;
- nenhum campo de senha pode aparecer em queries de retorno da API.

### 4.2 `refresh_tokens`

Usar o modelo definido em 2.6, com índices em:

- `user_id`;
- `family_id`;
- `expires_at`;
- `token_hash`, se ele for usado diretamente para busca;
- tokens ativos, quando um índice parcial trouxer benefício mensurável.

As FKs devem impedir tokens órfãos. A política de exclusão de usuário deverá ser
definida antes da migration; como exclusão de conta não pertence à V1, não criar
endpoint nem cascade destrutivo agora.

## 5. Contrato HTTP da V1

| Método | Rota | Autenticação | Resultado principal |
| --- | --- | --- | --- |
| GET | `/health` | pública | estado do processo e banco |
| POST | `/api/v1/auth/register` | pública | `201` com usuário |
| POST | `/api/v1/auth/login` | pública | `200` com par de tokens |
| POST | `/api/v1/auth/refresh` | refresh token | `200` com novo par |
| POST | `/api/v1/auth/logout` | refresh token | `204` |
| GET | `/api/v1/users/me` | Bearer JWT | `200` com usuário atual |
| GET | `/.well-known/jwks.json` | pública | conjunto de chaves públicas |
| GET | `/openapi.json` | pública em dev | OpenAPI 3.1 |
| GET | `/docs` | pública em dev | documentação interativa |

Decisões de contrato a fechar na fase inicial:

- refresh token será enviado em corpo JSON na V1, seguindo o contrato atual;
- nomes JSON serão camelCase (`accessToken`, `refreshToken`, `tokenType`,
  `expiresIn`);
- logout válido será idempotente apenas enquanto for possível identificar a
  família; token malformado ou desconhecido retornará resposta genérica;
- documentação poderá ser desabilitada por configuração em produção.

## 6. Fases de implementação

### Fase 0 — Congelar decisões e contratos

Tarefas:

- [x] confirmar política de senha entre 12 e 128 bytes;
- [x] confirmar expiração absoluta da família de refresh tokens;
- [x] exigir claim `aud`, configurável por `JWT_AUDIENCE` e com valor padrão
  `auth-api`;
- [x] usar `golang-jwt/jwt/v5`, serialização JWK RSA local coberta por testes e
  `golang-migrate` com driver pgx;
- [x] definir `/docs`, OpenAPI e schemas como desabilitados por padrão em
  produção, com opt-in explícito;
- [x] formalizar schemas Huma de request, response e erro;
- [x] criar exemplos válidos na documentação Swagger/OpenAPI.

Critério de aceite:

- nenhum ponto acima permanece implícito antes das migrations e dos contratos
  públicos serem implementados.

### Fase 1 — Fundação da aplicação

Status: em andamento. O primeiro incremento desta fase foi implementado na
branch `v1`.

Tarefas:

- [x] separar construção da aplicação do `main` para facilitar testes;
- [x] validar todas as configurações na inicialização, sem fallbacks silenciosos
  para valores inválidos;
- [x] criar logger `slog` configurado por ambiente;
- [x] adicionar middlewares Chi de request ID, recovery e logging estruturado;
- [x] configurar Huma com metadados da API e security scheme `bearerAuth`;
- [x] padronizar o modelo de erro do Huma;
- [x] manter shutdown gracioso e timeouts HTTP;
- [x] adicionar testes do carregamento de configuração e do router básico.

Critério de aceite:

- processo inicia com configuração válida, falha rapidamente com configuração
  inválida e publica OpenAPI contendo health e JWKS.

### Fase 2 — PostgreSQL e migrations

Status: em andamento. O pool pgx, as migrations iniciais, o binário de
migrations e o encadeamento no Compose foram implementados na branch `v1`.

Tarefas:

- [x] adicionar `pgxpool` e construir o pool no startup;
- [x] configurar limites do pool, tempo de conexão e health check;
- [x] criar migration `users`;
- [x] criar migration `refresh_tokens` com suporte à rotação;
- [x] criar migrations de rollback correspondentes;
- [x] criar comando documentado para `migrate up/down`;
- [x] fazer `/health` verificar o banco com timeout curto;
- [x] encerrar o pool durante o shutdown;
- [x] adicionar teste de aplicação e rollback das migrations em banco limpo.

Critério de aceite:

- Compose sobe PostgreSQL saudável, aplica migrations e a aplicação consegue
  executar `Ping`; migrations sobem e descem de forma reproduzível.

### Fase 3 — Segurança criptográfica básica

Status: em andamento. O hashing Argon2id, carregamento de chaves RSA, emissão
de access token RS256 e JWKS foram implementados na branch `v1`.

Tarefas:

- [x] implementar geração e verificação de hash Argon2id em formato PHC;
- [x] validar e carregar chaves RSA PEM no startup;
- [x] rejeitar chave ausente, inválida ou abaixo do tamanho mínimo definido;
- [x] calcular um `kid` estável para a chave pública;
- [x] implementar assinatura e validação local de JWT RS256;
- [x] implementar geração de refresh token com CSPRNG;
- [x] implementar hash e comparação constante do refresh token;
- [x] preencher o endpoint JWKS com a chave RSA pública real;
- [x] criar testes unitários para todos os casos criptográficos e de expiração.

Critério de aceite:

- token assinado pelo serviço é validado pela chave obtida no JWKS; chaves,
  hashes e tokens inválidos são rejeitados sem panic ou vazamento de dados.

### Fase 4 — Cadastro de usuário

Status: em andamento. O domínio, service, repository PostgreSQL e endpoint Huma
de cadastro foram iniciados na branch `v1`.

Tarefas:

- [x] criar modelo e repository de usuário;
- [x] implementar normalização de e-mail;
- [x] implementar validações de nome, e-mail e senha nos schemas Huma;
- [x] criar o caso de uso de cadastro;
- [x] gerar hash antes da persistência;
- [x] tratar violação UNIQUE como `email_already_exists`/`409`;
- [x] garantir role `USER` independentemente do payload;
- [x] registrar `POST /api/v1/auth/register` no Huma;
- [x] não retornar nem logar `password_hash`;
- [x] adicionar testes unitários, de repository e HTTP.

Critério de aceite:

- cadastro válido retorna `201`; e-mail inválido, senha inválida, campos ausentes
  e duplicidade retornam erros estáveis e documentados.

### Fase 5 — Login e emissão de sessão

Status: em andamento. A busca de usuário, verificação de senha, emissão de
access token e persistência do primeiro refresh token foram implementadas na
branch `v1`.

Tarefas:

- [x] buscar usuário por e-mail normalizado;
- [x] verificar senha com comportamento equivalente para usuário ausente;
- [x] emitir JWT com claims e TTL definidos;
- [x] criar refresh token e persistir somente seu hash;
- [x] criar `family_id` para a nova sessão;
- [x] persistir sessão antes de devolver tokens;
- [x] registrar `POST /api/v1/auth/login`;
- [x] responder `invalid_credentials` tanto para e-mail inexistente quanto para
  senha incorreta;
- [x] testar claims, assinatura e ausência de dados sensíveis;
- [x] testar expiração do access token.

Critério de aceite:

- credenciais válidas retornam access e refresh tokens utilizáveis; credenciais
  inválidas retornam `401` sem permitir enumeração de usuário.

### Fase 6 — Autenticação Bearer e `/users/me`

Status: em andamento. O middleware Huma de Bearer, validação RS256 e o endpoint
`/api/v1/users/me` foram implementados na branch `v1`.

Tarefas:

- [x] implementar middleware Huma que identifica operações com `bearerAuth`;
- [x] extrair Bearer token de forma rigorosa;
- [x] validar assinatura, algoritmo, issuer e expiração;
- [x] colocar identidade tipada no contexto;
- [x] expor a identidade do usuário a partir do `sub` e claims do JWT;
- [x] registrar `GET /api/v1/users/me` com security scheme no OpenAPI;
- [x] responder `401` para token ausente/inválido/expirado;
- [x] testar autorização no handler e o botão Authorize da documentação.

Critério de aceite:

- um token emitido no login acessa `/users/me`; tokens expirados, adulterados ou
  emitidos por outro issuer são rejeitados.

### Fase 7 — Rotação de refresh token

Status: em andamento. A rotação transacional, encadeamento, detecção de
reutilização e endpoints de refresh/logout foram implementados na branch `v1`.

Tarefas:

- [x] interpretar seletor e segredo sem expor o token em erros;
- [x] localizar e bloquear a linha do token em transação;
- [x] validar hash, expiração, revogação e estado de uso;
- [x] marcar o token atual como usado;
- [x] emitir novo JWT e novo refresh token;
- [x] inserir o novo token na mesma família e ligar a cadeia;
- [x] confirmar toda a rotação em uma única transação;
- [x] detectar reutilização e revogar a família inteira;
- [x] registrar `POST /api/v1/auth/refresh`;
- [x] testar duas requisições concorrentes usando o mesmo token.

Critério de aceite:

- somente uma rotação concorrente tem sucesso; o token anterior deixa de
  funcionar e uma tentativa de reutilização invalida a sessão comprometida.

### Fase 8 — Logout e revogação

Status: em andamento. O logout por refresh token e a revogação da família foram
implementados na branch `v1`.

Tarefas:

- [x] validar o refresh token recebido;
- [x] revogar todos os tokens ativos da família em transação;
- [x] registrar `POST /api/v1/auth/logout`;
- [x] definir resposta segura para token desconhecido, expirado ou já revogado
  como `401 invalid_token`, sem ecoar o token;
- [x] testar que o access token atual continua válido até expirar;
- [x] testar que nenhum refresh da família funciona após logout.

Critério de aceite:

- logout impede novas renovações da sessão sem exigir uma blacklist de access
  tokens, preservando a natureza stateless do JWT.

### Fase 9 — Observabilidade e hardening HTTP

Status: concluída para o escopo da V1. Logging estruturado, limites de corpo,
headers de segurança e defaults seguros de produção estão ativos e testados.

Tarefas:

- [x] emitir logs JSON com timestamp, level, request ID, método, path, status e
  duração;
- [x] revisar redaction de headers, corpos e erros;
- [x] configurar limites de tamanho do corpo e timeouts;
- [x] manter CORS desabilitado enquanto não houver acesso direto por frontend e
  documentar allowlist obrigatória para essa evolução;
- [x] adicionar headers de segurança aplicáveis;
- [x] não adicionar métricas na V1 enquanto não houver infraestrutura para
  coletá-las;
- [x] documentar HTTPS obrigatório fora do ambiente local;
- [x] revisar mensagens para evitar enumeração de contas.

Critério de aceite:

- fluxos podem ser correlacionados por request ID e nenhum teste/log contém
  senha, access token, refresh token ou hash completo.

### Fase 10 — Testes de sistema e qualidade

Tarefas:

- [x] cobrir services com testes de unidade e relógio controlável;
- [x] cobrir repositories contra PostgreSQL real;
- [x] cobrir handlers com `httptest` e Huma;
- [x] executar o fluxo completo da seção 29 do design;
- [x] testar rollback quando uma rotação falha no meio da transação;
- [x] testar concorrência e executar `go test -race ./...`;
- [x] validar `go test`, `go vet`, formatação e análise de vulnerabilidades;
- [x] validar que OpenAPI inclui contratos, erros e autenticação;
- [x] criar fixtures sem credenciais reais.

Critério de aceite:

- toda a matriz de testes da seção 25 do design passa localmente e em ambiente
  limpo, incluindo reutilização e concorrência de refresh token.

### Fase 11 — Container, CI e entrega

Status: em andamento. A imagem inclui os binários da API e migrations, roda
como usuário não-root e o Compose encadeia banco, migrations e API.

Tarefas:

- [x] ajustar Dockerfile para cache de módulos com `go.sum`;
- [x] manter imagem final mínima e usuário não-root;
- [x] montar chaves por secret/volume, nunca por `COPY` no build;
- [x] adicionar healthcheck ao PostgreSQL e à API no Compose;
- [x] definir como migrations rodam antes da aplicação;
- [x] adicionar pipeline de CI para build, testes, race, vet e vulnerabilidades;
- [x] documentar geração de chaves apenas para desenvolvimento;
- [x] documentar configuração de produção e rotação futura de chaves;
- [x] produzir binário e imagem reproduzíveis.

Critério de aceite:

- um checkout limpo consegue subir banco e serviço seguindo apenas o README, e
  o fluxo completo funciona via HTTP/Swagger.

## 7. Estratégia de testes

### Unitários

- normalização e validação de e-mail;
- política e hashing de senha;
- parsing de PHC;
- claims e expiração de JWT;
- geração/hash de refresh token;
- mapeamento de erros de domínio para HTTP;
- casos de uso com repositories falsos.

### Integração

- migrations;
- constraints e índices;
- repositories com PostgreSQL;
- transações de rotação e logout;
- concorrência com duas conexões;
- rollback em erro.

### HTTP/contrato

- status, headers e corpos de todas as rotas;
- validação automática do Huma;
- security scheme e schemas OpenAPI;
- Bearer válido e inválido;
- erros sem dados internos;
- fluxo completo de cadastro até logout.

Testes dependentes de tempo deverão receber um relógio injetável. Testes de
segurança não devem depender de `time.Sleep` nem de chaves de produção.

## 8. Ordem recomendada dos primeiros incrementos

Cada incremento deve terminar compilando e com testes verdes:

1. configuração, logger, erros e composição da aplicação;
2. conexão pgx e migrations;
3. Argon2id e repository de usuário;
4. cadastro;
5. chaves RSA, JWT e JWKS;
6. login e criação de sessão;
7. middleware Bearer e `/users/me`;
8. refresh com rotação e detecção de reutilização;
9. logout;
10. hardening, testes de sistema, Docker, CI e documentação final.

## 9. Definition of Done da V1

A V1 estará pronta quando:

- [x] usuário pode ser cadastrado com e-mail único e senha Argon2id;
- [x] login retorna access token RS256 e refresh token opaco;
- [x] outro serviço valida o JWT usando apenas o JWKS público;
- [x] `/users/me` retorna a identidade do token válido;
- [x] refresh rotaciona o token de forma atômica;
- [x] reutilização de refresh token é detectada e revoga a família;
- [x] logout impede qualquer nova renovação da sessão;
- [x] erros são consistentes e não permitem enumeração óbvia de usuários;
- [x] logs são estruturados e não contêm segredos;
- [x] Swagger/OpenAPI descreve todas as rotas, schemas e autenticação;
- [ ] migrations, testes, Docker e instruções funcionam em checkout limpo;
- [x] todas as condições da seção 29 do design foram demonstradas.

## 10. Itens explicitamente adiados

Permanecem fora da V1:

- recuperação e confirmação de e-mail;
- MFA e login social;
- OAuth2/OIDC completo;
- múltiplas roles, permissions e scopes;
- painel de sessões/dispositivos;
- revogação imediata de access token;
- rate limiting distribuído e Redis;
- auditoria completa e histórico de login;
- rotação automática de múltiplas chaves;
- API administrativa para conceder `ADMIN`.

Esses itens não devem bloquear nem aumentar a complexidade da primeira versão.
