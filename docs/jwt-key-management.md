# Gerenciamento de chaves JWT

O serviço assina access tokens com RS256. Somente o Auth Service deve ter acesso
à chave privada; serviços consumidores usam a chave pública disponibilizada em
`/.well-known/jwks.json`.

## Desenvolvimento local

As chaves em `certs/` são exclusivas do ambiente local, estão ignoradas pelo Git
e nunca devem ser reutilizadas em staging ou produção.

Crie um novo par com OpenSSL:

```bash
mkdir -p certs
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out certs/jwt.private.pem
openssl pkey -in certs/jwt.private.pem -pubout -out certs/jwt.public.pem
chmod 600 certs/jwt.private.pem
chmod 644 certs/jwt.public.pem
```

O serviço exige RSA com pelo menos 2048 bits e falha na inicialização se as
chaves estiverem ausentes, forem inválidas ou não formarem um par. Para conferir
o tamanho e comparar o material público derivado de cada arquivo:

```bash
openssl pkey -in certs/jwt.private.pem -text_pub -noout
openssl pkey -in certs/jwt.private.pem -pubout -outform DER | openssl dgst -sha256
openssl pkey -pubin -in certs/jwt.public.pem -outform DER | openssl dgst -sha256
```

Os dois hashes SHA-256 devem ser iguais. Eles identificam o material público e
não são segredos.

Para descartar as chaves locais, remova somente os dois arquivos `.pem` de
`certs/` e gere um novo par antes de iniciar novamente a aplicação.

## Configuração em produção

Gere e armazene o par em um gerenciador de segredos ou mecanismo equivalente do
orquestrador. Monte cada chave como arquivo somente leitura no container e
configure os caminhos:

```dotenv
APP_ENV=production
JWT_PRIVATE_KEY_PATH=/run/secrets/auth-jwt-private.pem
JWT_PUBLIC_KEY_PATH=/run/secrets/auth-jwt-public.pem
JWT_ISSUER=auth-service
JWT_AUDIENCE=auth-api
ACCESS_TOKEN_TTL=15m
```

Requisitos operacionais:

- nunca inserir a chave privada na imagem, no Git, em variáveis de ambiente, em
  argumentos de linha de comando ou em logs;
- limitar a leitura da chave privada à identidade que executa o Auth Service;
- entregar somente a chave pública aos serviços consumidores, preferencialmente
  por meio do endpoint JWKS;
- manter versões, controle de acesso, auditoria e recuperação no gerenciador de
  segredos;
- atualizar os dois arquivos como um único par e reiniciar a aplicação, pois as
  chaves são carregadas durante a inicialização;
- verificar `/health` e `/.well-known/jwks.json` após cada implantação.

O `kid` é calculado a partir da chave pública. Portanto, um novo par produz um
novo `kid` automaticamente.

## Rotação e resposta a incidentes

Na V1, o serviço publica apenas a chave ativa. Trocar o par remove imediatamente
a chave pública anterior do JWKS, fazendo com que access tokens antigos deixem
de ser aceitos assim que os consumidores atualizarem o cache. Refresh tokens não
são JWTs e continuam sujeitos às regras de sessão armazenadas no PostgreSQL.

Em caso de suspeita de comprometimento, a invalidação imediata é desejável:

1. gere uma nova versão do par no gerenciador de segredos;
2. substitua os dois arquivos de forma coordenada e reinicie o serviço;
3. confirme que o JWKS apresenta o novo `kid`;
4. force os consumidores a atualizar o JWKS;
5. revogue o acesso à chave anterior e investigue o incidente.

Para uma rotação programada sem invalidar access tokens ainda válidos, a evolução
futura deverá suportar múltiplas chaves:

1. publicar a nova chave pública no JWKS junto com a anterior;
2. passar a assinar novos tokens com o novo `kid`;
3. manter a chave pública anterior por pelo menos o maior TTL de access token,
   somado à tolerância de cache dos consumidores;
4. remover a chave pública anterior e destruir sua chave privada.

Essa rotação sem interrupção ainda não é implementada na V1. Até que o suporte a
múltiplos `kid` exista, rotações programadas devem assumir uma janela coordenada
de invalidação dos access tokens existentes.
