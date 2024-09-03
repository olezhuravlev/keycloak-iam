### How to export a realm

1. Login to the Docker container shell:

```text
$ docker exec -it keycloak bash
```

2. Proceed to the Keycloak directory `/opt/keycloak/bin`;

3. Run export procedure `./kc.sh export --file <FILE_NAME> --realm <REALM_NAME>`:

```text
bash-5.1$ ./kc.sh export --file realm-myrealm-exported.json --realm myrealm
2024-08-23 08:36:06,423 INFO  [org.keycloak.quarkus.runtime.hostname.DefaultHostnameProvider] (main) Hostname settings: Base URL: <unset>, Hostname: <request>, Strict HTTPS: false, Path: <request>, Strict BackChannel: false, Admin URL: <unset>, Admin: <request>, Port: -1, Proxied: false
2024-08-23 08:36:07,353 WARN  [io.quarkus.agroal.runtime.DataSources] (main) Datasource <default> enables XA but transaction recovery is not enabled. Please enable transaction recovery by setting quarkus.transaction-manager.enable-recovery=true, otherwise data may be lost if the application is terminated abruptly
2024-08-23 08:36:07,641 WARN  [org.infinispan.PERSISTENCE] (keycloak-cache-init) ISPN000554: jboss-marshalling is deprecated and planned for removal
2024-08-23 08:36:07,703 INFO  [org.infinispan.CONTAINER] (keycloak-cache-init) ISPN000556: Starting user marshaller 'org.infinispan.jboss.marshalling.core.JBossUserMarshaller'
2024-08-23 08:36:07,967 INFO  [org.keycloak.connections.infinispan.DefaultInfinispanConnectionProviderFactory] (main) Node name: node_822364, Site name: null
2024-08-23 08:36:08,271 INFO  [org.keycloak.broker.provider.AbstractIdentityProviderMapper] (main) Registering class org.keycloak.broker.provider.mappersync.ConfigSyncEventListener
2024-08-23 08:36:08,580 INFO  [org.keycloak.services] (main) KC-SERVICES0034: Export of realm 'myrealm' requested.
2024-08-23 08:36:08,580 INFO  [org.keycloak.exportimport.singlefile.SingleFileExportProvider] (main) Exporting realm 'myrealm' into file /opt/keycloak/bin/realm-myrealm-exported.json
2024-08-23 08:36:08,965 INFO  [org.keycloak.services] (main) KC-SERVICES0035: Export finished successfully
2024-08-23 08:36:09,001 INFO  [io.quarkus] (main) Keycloak 22.0.0 on JVM (powered by Quarkus 3.2.0.Final) started in 3.178s. Listening on: 
2024-08-23 08:36:09,001 INFO  [io.quarkus] (main) Profile import_export activated. 
2024-08-23 08:36:09,001 INFO  [io.quarkus] (main) Installed features: [agroal, cdi, hibernate-orm, jdbc-h2, jdbc-mariadb, jdbc-mssql, jdbc-mysql, jdbc-oracle, jdbc-postgresql, keycloak, logging-gelf, micrometer, narayana-jta, reactive-routes, resteasy, resteasy-jackson, smallrye-context-propagation, smallrye-health, vertx]
2024-08-23 08:36:09,024 INFO  [io.quarkus] (main) Keycloak stopped in 0.021s
```

4. On local machine the exported file can be found in local Docker container file:

```text
$ sudo find / -name "realm-myrealm-exported.json" -type f
/var/snap/docker/common/var-lib-docker/overlay2/.../diff/opt/keycloak/bin/realm-myrealm-exported.json
```

It's a sudo directory so copy the file to the accessible location:

```text
$ sudo cp /var/snap/docker/common/var-lib-docker/overlay2/10208ebe783a5c88abdd50a8b9503c5c9dc812c05016f17758af4edcff6ebcdb/diff/opt/keycloak/bin/realm-myrealm-exported.json /home/oleg/MyProjects/keycloak-iam/keycloak/config
```

And change the access:

```text
$ ls -la
total 76
drwxrwxr-x 2 oleg oleg  4096 авг 23 11:42 .
drwxrwxr-x 3 oleg oleg  4096 авг 23 09:31 ..
-rw-r--r-- 1 root root 66617 авг 23 11:42 realm-myrealm-exported.json

 11:43:05  oleg@oleg-desktop-linux  ...keycloak-iam/keycloak/config  ⬡ v20.16.0 
$ sudo chown oleg:oleg realm-myrealm-exported.json 
[sudo] password for oleg: 

 11:43:21  oleg@oleg-desktop-linux  ...keycloak-iam/keycloak/config  ⬡ v20.16.0 
$ ls -la
total 76
drwxrwxr-x 2 oleg oleg  4096 авг 23 11:42 .
drwxrwxr-x 3 oleg oleg  4096 авг 23 09:31 ..
-rw-r--r-- 1 oleg oleg 66617 авг 23 11:42 realm-myrealm-exported.json

```

File to be imported by Keycloak during startup must be located in Docker container
path: `/opt/keycloak/data/import/realm-myrealm-exported.json`

---

User console:
http://localhost:8080/realms/myrealm/account/#/

---

---

# 2. Простая защита приложения

## Процедура авторизации "OpenID Connect"

#### Обмен данными между фронтендом и Keycloak:

1. Пользователь жмет на кнопку "Login";
2. Приложение перенаправляется на страницу логина Keycloak;
3. Keycloak отображает страницу логина пользователю;
4. Пользователь заполняет учётные данные (имя и пароль) и отправляет их в Keycloak;
5. Keycloak проверяет полученные учётные данные, генерирует `Authorization code` и отправляет его приложению;

> CORS-запросы д.б. разрешены в Keycloak, для этого в параметре `Web origins` в настройках клиента Keycloak д.б. указан URL приложения без
> завершающего слэша - например, `http://localhost`
>
> Также можно указать `*`, но это небезопасно!

6. Приложение обменивает имеющийся у него `Authorization code` на два токена - `ID Token` и `Access Token`. Теперь приложение сможет
   проверять подлинность пользователя, используя `ID Token` и получать данные, используя `Access Token`.
7. Пользователю отображается страница аутентифицированного пользователя.

![auth_code_flow.jpg](img/auth_code_flow_frontend.jpg)

#### Токены, генерируемые Keycloak:

<table>
<tr align="center">
<td> <b>ID Token</b> </td> <td> <b>Access Token</b> </td>
</tr>
<tr  valign="top">
<td>

```json
{
  "exp": 1725098762,
  "iat": 1725098462,
  "auth_time": 1725098459,
  "jti": "d7108acc-d082-4078-9db0-25e67427fcff",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "myclient",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "ID",
  "azp": "myclient",
  "nonce": "e6b3ed86-2087-43f0-bcf1-287a5bff060e",
  "session_state": "a1e5f9e2-9cde-43ba-9237-8faed3e8d282",
  "at_hash": "H0Qo_SKblXwIP0_NQODaNg",
  "acr": "1",
  "sid": "a1e5f9e2-9cde-43ba-9237-8faed3e8d282",
  "email_verified": true,
  "name": "UserFirstName UserLastName",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName",
  "family_name": "UserLastName",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak@keycloak.org"
}
```

</td>
<td>

```json
{
  "exp": 1725098762,
  "iat": 1725098462,
  "auth_time": 1725098459,
  "jti": "888c0ae8-cce4-4341-a066-18f9afca6234",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "account",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "Bearer",
  "azp": "myclient",
  "nonce": "e6b3ed86-2087-43f0-bcf1-287a5bff060e",
  "session_state": "a1e5f9e2-9cde-43ba-9237-8faed3e8d282",
  "acr": "1",
  "allowed-origins": [
    "http://localhost:8000"
  ],
  "realm_access": {
    "roles": [
      "default-roles-myrealm",
      "offline_access",
      "uma_authorization",
      "myrole"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid profile email",
  "sid": "a1e5f9e2-9cde-43ba-9237-8faed3e8d282",
  "email_verified": true,
  "name": "UserFirstName UserLastName",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName",
  "family_name": "UserLastName",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak@keycloak.org"
}
```

</td>
</tr>
<td>
</table>

---

#### Обмен данными между фронтендом и бекендом:

1. Бекенд получает от Keycloak публичные ключи (`Public keys`) и кэширует их памяти;
2. Фронтенд отправляет к бекенду запрос, включив в него `Access token`;
3. Бекенд использует имеющиеся `Public keys` для верификации полученного от фронтенда `Access token` (проверяет, был ли этот `Access token`
   выпущен Keycloak, является ли он валидным и содержит ли требуемые роли);
4. Бекенд возвращает результат фронтенду.

![auth_code_flow_backend.jpg](img/auth_code_flow_backend.jpg)

---

---

# 3. Основные стандарты

## OAuth 2.0 - индустриальный стандарт протокола авторизации (не аутентификации!)

Позволяет делиться пользовательскими данными с третьей стороной:

- прост в использовании;
- не требуется раскрывать учётные данные пользователя;
- позволяет контролировать, какими именно данными делиться.

#### Роли в OAuth 2.0

- `Resource owner` - конечный пользователь, владеющий ресурсами, к которым приложению нужно получить доступ;
- `Resource server` - сервис, содержащий защищенные ресурсы;
- `Client` - приложение, желающее получить доступ к защищенным ресурсам;
- `Authorization server` - сервер, выдающий доступ клиенту (а данном случае это Keycloak).

#### Актуальные процедуры аутентификации (Authentication Flows):

- **Client Credentials Flow** - приложение само является владельцем ресурса (`Resource Owner`) и получает доступ от своего имени;
- **Device Flow** - приложение запущено на устройстве, где нет браузера или нет возможности вводить учётные данные пользователя (например, "
  Smart TV");
- **Authorization Code Flow** - все прочие случаи.

#### Устаревшие процедуры аутентификации:

- **Implicit Flow** - упрощенная процедура для нативных (без браузера) и клиентских приложений;
- **Resource Owner Password Credentials flow** - приложение принимает учётные данных пользователя и обменивает их на `Access Token` (подход
  является небезопасным, т.к. учётные данные пользователя напрямую предоставляются приложению);

---

### Процесс авторизации OAuth 2.0

Пользователь нажимает кнопку "Login" и после этого:

1. Приложение создаёт `Authorization Request`, предписывающий браузеру пользователя перейти на `Authorization Endpoint` Keycloak;
2. Браузер пользователя переходит на `Authorization Endpoint` Keycloak;
3. Если пользователь еще не аутентифицирован, то Keycloak аутентифицирует пользователя и предлагает пользователю разрешить приложению доступ
   к сервису от имени пользователя;
4. Приложение получает от Keycloak `Authorization Response` содержащий `Authorization Code` внутри;
5. Приложение генерирует `Access Token Request` к `Token Endpoint` Keycloak с целью обменять имеющийся `Authorization Code`
   на `Access Token`;
6. Приложение использует полученный `Access token` для обращения к защищенным ресурсам.

![oauth2_code_flow.jpg](img/oauth2_code_flow.jpg)

---

### Типы клиентов OAuth 2.0

- **Confidential clients** - приложения, которые могут безопасно хранить учётные данные пользователя (например, серверные веб-приложения),
  чтобы использовать их для аутентификации на сервере авторизации;
- **Public clients** - клиентские приложения, которые не могут безопасно хранить учётные данные пользователя.

Т.е. публичные клиенты не могут проходить аутентификацию на сервере авторизации, то предусмотрены две меры безопасности:

- сервер авторизации отправит код авторизации только приложению, размещённому на определённом URL-адресе;
- даже если кто-то перехватит код авторизации, то **Proof Key for Code Exchange** (PKCE, RFC 7636) (расширение OAuth 2.0), не
  позволит обменять его на токен доступа.

---

Для повышения безопасности `Access Token` делается короткоживущим. А чтобы не заставлять пользователя повторно проходить всю процедуру
аутентификации, новый `Access Token` м.б. получен с использованием `Refresh Token`, который д.б. надёжно сохранён.

---

### Прочие спецификации

- **Bearer Tokens (RFC 6750)** : часто используемый тип токенов, обычно отправляемых на ресурсный сервер в HTTP-заголовке `Authorization`.
  Также могут передаваться в теле запроса или как параметр запроса, что является небезопасным. Не являются частью OAuth 2.0;
- **Token Introspection (RFC 7662)**: в OAuth 2.0 содержимое `Access Tokens` недоступно для приложений, а точка
  доступа `Token Introspection`
  позволяет клиенту получить информацию об `Access Tokens` не зная его формата;
- **Token Revocation (RFC 7009)**: Точка доступа `Token Revocation` позволяет отозвать `Access Token` т.к. OAuth 2.0 регламентирует
  выдачу токенов приложению, но не регламентирует их отзыв.

---

## OpenID Connect (OIDC) - индустриальный стандарт протокола аутентификации

Построен на базе OAuth 2.0.

Позволил:

- производить аутентификацию через соцсети;
- реализовать SSO (Single-Sign On);
- сохранять в тайне учётные данные пользователя, не предоставляя их приложениям;
- использовать сильные методы аутентификации (#, OTP, WebAuthn), не реализуя их в самих приложениях;
- предоставлять доступ к ресурсам организации третьим лицам (#, партнёрам) без необходимости создавать для них учётные записи предприятия;

#### Роли протокола OIDC (OpenID Connect):

- **End User**: аутентифицируемый человек, аналог владельца ресурса (`Resource Owner`) в OAuth 2.0;
- **Relying Party (RP)**: приложение, которое хотело бы аутентифицировать конечного пользователя;

> Называется `Relying Party` ("Доверяющая Сторона"), поскольку это сторона, которая полагается на OpenID Provider (OP) для проверки личности
> пользователя.

- **OpenID Provider (OP)**: поставщик удостоверений, аутентифицирующий пользователя (здесь это **Keycloak**).

> RP запрашивает идентификацию конечного пользователя у OP, а т.к. он строится поверх OAuth 2.0, то одновременно он может получить и токен
> доступа.

#### Потоки OIDC (OpenID Connect):

- **Authorization code flow** (поток кода авторизации): он использует тот же поток, что и тип предоставления кода авторизации OAuth 2.0, и
  возвращает код авторизации, такой как OAuth 2.0, который можно обменять на токен идентификатора, токен доступа и токен обновления.
- **Hybrid flow** (Гибридный поток): в гибридном потоке токен идентификатора возвращается из первоначального запроса вместе с кодом
  авторизации.

---

#### Дополнительные спецификации, используемые в OIDC (OpenID Connect) (но не входящие в OIDC Core Specification):

- **Discovery**: Позволяет клиенту динамически получать информацию о поставщике удостоверений (`OpenID Provider, OP`);
- **Dynamic Registration**: Позволяет клиентам динамически регистрироваться в поставщике удостоверений (`OpenID Provider, OP`);
- **Session Management**: Определяет способ отслеживания аутентифицированной сессии пользователя с помощью поставщика
  удостоверений (`OpenID Provider, OP`) и инициирование клиентом логаута;
- **Front-Channel Logout**: Определяет механизм единого выхода из системы (`SSO, Single-Sign Out`) для набора приложений, используя
  встроенные `iframe`-мы;
- **Back-Channel Logout**: Определяет механизм единого выхода из системы (`SSO, Single-Sign Out`) для набора приложений, используя механизм
  запроса по обратному каналу (`Back-Channel Request Mechanism`).

---

### OIDC (OpenID Connect) использует еще две концепции:

- формат `ID Token` на основе JWT-спецификации, что делает его прозрачным и клиент может его прочитать и получить информацию
  об аутентифицированном пользователе;

> Хотя OIDC и определяет стандартный формат для `ID Token`, но при этом он никак не определяет формат для `Access Token`!

- точку доступа с информацией о пользователе (`Userinfo Endpoint`), к которой можно обратиться, предоставив `Access Token`, для получения
  информации, аналогичной содержащейся в `ID Token`.

**Financial-Grade API (FAPI)** - набор профилей, применяемых в случае повышенных требований к безопасности. Не имеет исключительного
отношения к финансам, а просто предназначен для высокорисковых сценариев.

---

## Использование JWT (JSON Web Token) в качестве токенов Keycloak

> **JOSE (JavaScript Object Signing and Encryption)** - набор спецификаций, послуживший основой для создания JWT.

JWT используется в целях совместимости и простоты интеграции.
Кроме того, его использование избавляет ресурсные серверы от необходимости выполнять запросы к точкам
доступа Keycloak `OAuth 2.0 Token Introspection`, или `OIDC UserInfo`.

### Спецификации, связанные с JWT:

- **JSON Web Token (JWT, RFC 7519)**: состоит из двух base64url-кодированных JSON документов, разделенных точкой - заголовок и полезная
  нагрузка;
- **JSON Web Signature (JWS, RFC 7515)**: Добавляет цифровую подпись к заголовку и полезной нагрузке;
- **JSON Web Encryption (JWE, RFC 7516)**: Шифрует полезную нагрузку;
- **JSON Web Algorithms (JWA, RFC 7518)**: Определяет криптографические алгоритмы, которые должны поддерживаться JWS и JWE.
- **JSON Web Key (JWK, RFC 7517)**: Определяет формат для представления криптографических ключенй в JSON-формате.

Точка доступа `OIDC Discovery` сообщит о точке доступа, из которой м.б. получен набор `JWK` - `JWKS (JSON Web Key Set)` - а также
о поддерживаемых механизмах подписи и шифрования.

### Верификация `Access Token`:

Когда ресурсный сервер получает `Access Token`, то он может **верифицировать** этот токен следующими способами:

- получением `JWKS URL` из точки доступа `OIDC Discovery`;
- скачиванием публичных ключей подписания для `OP` (`OpenID Provider`) из точки доступа `JWKS URL` (при этом ключи обычно кешируются
  ресурсным сервером);
- проверкой подписи токена используя публичные ключи подписания из `OP` (`OpenID Provider`).

### Потенциальные уязвимости JWT-спецификации:

- **alg=none**: Спецификация JWS определяет `none` как допустимое значение алгоритма, что означает, что JWS не подписан. Соответственно,
  JWT-библиотека сообщит о неподписанном JWS как о валидном;

> Не следует принимать `alg=none`!

- **RSA to HMAC**: Использование публичного RSA-ключа при указанном алгоритме `hmac`. Некоторые библиотеки слепо принимают такое значение
  токена просто используя публичный ключ в качестве секретного `HMAC`-ключа.

> Ключ должен использоваться только по своему предназначению и не следует слепо доверять значениям в заголовке JWT!

---

## SAML 2.0 - протокол аутентификации и авторизации

Зрелый протокол (ратифицирован как `OASIS Standard` с 2005г.), широко используемый для реализации `SSO (Single Sign-On)` в корпоративных
системах, включая их
SAAS-реализации.

По сравнению с `SAML 2.0` протокол `OIDC` проще в понимании за счет использования JSON и простых параметров запросов.

Кроме того, `OIDC` более сфокусирован на современных архитектурах, как SPA (Single-Page Application), мобильных приложениях, REST
API и микросервисах.

#### Keycloak позволяет использовать оба протокола - и `SAML 2.0` и `OIDC`!

---

## Спецификация OpenID Discovery

Если `OpenID Provider` реализует спецификацию `OpenID Discovery`, то он предоставляет метаданные (`OpenID Provider Metadata`) по
стандартному URL вида `<Issuer URL>/.well-known/openid-configuration`. Keycloak реализует `OpenID Discovery`.

В случае с Keycloak, запущенному на порту `8080` для области с именем `myrealm`, `Issuer URL` имеет следующий вид:

```bash
curl http://localhost:8080/realms/myrealm | jq
````

> (jq - инструмент для форматирования выводимого JSON)

Тогда получить `OpenID Provider Metadata` можно по URL:

```bash
curl http://localhost:8080/realms/myrealm/.well-known/openid-configuration | jq
```

#### Будут возвращены URL:

| № | Точка доступа                         | URL                                                 | Назначение                                                                            |
|---|---------------------------------------|-----------------------------------------------------|---------------------------------------------------------------------------------------|
|   | Issuer URL                            | http://localhost:8080/realms/myrealm                | Корневой URL Keycloak                                                                 |
|   | OIDC Provider Configuration           | /.well-known/openid-configuration                   |                                                                                       |
|   | Registration Endpoint                 | /clients-registrations/openid-connect               |                                                                                       |
| 1 | Authorization Endpoint                | `/protocol/openid-connect`/auth                     | Обращение `Authentication Request` за авторизацией                                    |
|   | Device Authorization Endpoint         | `/protocol/openid-connect`/auth/device              |                                                                                       |
| 2 | Token Endpoint                        | `/protocol/openid-connect`/token                    | URL для `Token Request` и `Refresh Request` для обмена `Authorization Code` на токены |
|   | End Session Endpoint                  | `/protocol/openid-connect`/logout                   | URL для `Logout Request`                                                              |
|   | JWKS URI                              | `/protocol/openid-connect`/certs                    |                                                                                       |
|   | Backchannel Authentication Endpoint   | `/protocol/openid-connect`/ext/ciba/auth            |                                                                                       |
|   | Pushed Authorization Request Endpoint | `/protocol/openid-connect`/ext/par/request          |                                                                                       |
|   | Check Session IFrame                  | `/protocol/openid-connect`/login-status-iframe.html |                                                                                       |
|   | Revocation Endpoint                   | `/protocol/openid-connect`/revoke                   |                                                                                       |
|   | Introspection Endpoint                | `/protocol/openid-connect`/token/introspect         | URL для `Introspection request`                                                       |
|   | Userinfo Endpoint                     | `/protocol/openid-connect`/userinfo                 | URL для получения информации об аутентифицированном пользователе (`UserInfo Request`) |

Кроме того, возвращаются:

- `grant_types_supported`: Список поддерживаемых типов грантов:
    - `authorization_code` -
- `response_types_supported`: Список поддерживаемых типов ответов:
    - `code` - приложение желает получить авторизационный код (`Authorization Code`) от Keycloak;
    - `token` -

> Авторизационнй код имеет вид:
> `code=2f9bcd88-25c5-4f80-8195-29e1779a7bda.4f61dc0c-0dd6-4f89-adec-de3d0a45cdc7.8088567f-afe6-4d48-8927-e9d2e7bcdc1b`
> и используется приложением для получения `ID Token` и `Refresh Token`.

---

---
# 4. Процесс аутентификации OIDC (OpenID Connect)

1. Пользователь нажимает кнопку "Login";
2. Приложение создаёт `Authentication Request` (HTTP response 302);
3. Браузер пользователя получает указание (редирект) перейти на Keycloak;
4. Браузер пользователя переходит на `Authorization Endpoint` Keycloak отправляя ему параметры, заданные приложением
   в `Authentication Request`;
5. Если пользователь еще не аутентифицирован на Keycloak, то Keycloak его аутентифицирует, предоставляя страницу логина и верифицируя
   предоставленные учётные данные;
6. После успешной аутентификации пользователя приложение получает от Keycloak `Authentication Response`, содержащий в
   себе `Authorization Code`;
7. Приложение выполняет `Token Request` к `Token Endpoint` Keycloak для обмена полученного `Authorization Code` на `ID Token`
   и `Access Token` (а также и `Refresh Token`?). Обладая `ID token` приложение сможет идентифицировать личность пользователя и установить
   для него аутентифицированную сессию.

<table>
<tr align="center"><td><b>Figure 3.2: OpenId Connect authorization code flow simplified (page 31)</b></td><td><b>Figure 4.3: The authorization code flow (page 42)</b></td></tr>
<tr>
<td>

![openid_connect_auth_code_flow.jpg](img/openid_connect_auth_code_flow.jpg)</td>
<td>

![openid_connect_auth_code_flow_2.jpg](img/openid_connect_auth_code_flow_2.jpg)</td>
</tr>
</table>

#### (2) Приложение создаёт `Authentication Request` для перенаправления на Keycloak:

```text
http://localhost:8080/realms/myrealm/protocol/openid-connect/auth

client_id=oidc-playground
response_type=code
redirect_uri=http://localhost:8000/
scope=openid
login_hint=keycloak
```

Параметры `Authentication Request`:

- `client_id` - идентификатор клиента (приложения), зарегистрированного в Keycloak;
- `response_type`:
    - `code` - приложение желает от Keycloak получить `Authorization Code`;
- `redirect_uri` - URI, на который следует переслать пользователя после аутентификации;
- `scope` - запрашиваемый `scope`. Дефолтное значение - `openid`, что означает, что выполняется `OpenID`- запрос;
- `prompt`:
    - `none` - Keycloak не будет отображать экран логина, я только аутентифицирует пользователя, если он уже залогирован в Keycloack;
    - `login` - от пользователя потребуется залогиниться, даже если он уже залогинен в Keycloack;
- `max_age`: максимальное количество секунд, прошедших с последней аутентификации пользователя в Keycloak, не требующих повторной
  аутентификации;
- `login_hint` - если приложение знает имя пользователя, которого желает аутентифицировать, то в этом параметре можно это имя передать и оно
  будет отображено на странице логина.

#### (6) Keycloak аутентифицировал пользователя и в составе `Authentication Response` выдал авторизационный код (`Authorization Code`):

```text
code=b3df49c9-50a9-422d-ad70-80a1c0eeb588.4f61dc0c-0dd6-4f89-adec-de3d0a45cdc7.8088567f-afe6-4d48-8927-e9d2e7bcdc1b
```

> По дефолту, авторизационный код действителен в течение 1 минуты!

#### (7.1) Приложение отправляет `Token Request` на `Token Endpoint` Keycloak с целью обменять `Authorization Code` на токены:

```text
http://localhost:8080/realms/myrealm/protocol/openid-connect/token

grant_type=authorization_code
code=b3df49c9-50a9-422d-ad70-80a1c0eeb588.4f61dc0c-0dd6-4f89-adec-de3d0a45cdc7.8088567f-afe6-4d48-8927-e9d2e7bcdc1b
client_id=oidc-playground
redirect_uri=http://localhost:8000/
```

где:

- `code` - авторизационный код (`Authorization Code`), полученный ранее;
- `grant_type` - означает, что приложение желает обменять авторизационный код на токены;

> `Authorization Code` является одноразовым и м.б. использован только в одном `Token Request`!

#### (7.2) В ответ на `Token Request` приложение получает от Keycloak токены в составе `Token Response`:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjUzMTAwNzAsImlhdCI6MTcyNTMwOTc3MCwiYXV0aF90aW1lIjoxNzI1MzA5MjkwLCJqdGkiOiJmZmYwNGRmZS0yMGM1LTQ4NjgtODkwMC0yZWU5NTllZjFkMTIiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoib2lkYy1wbGF5Z3JvdW5kIiwic2Vzc2lvbl9zdGF0ZSI6IjRmNjFkYzBjLTBkZDYtNGY4OS1hZGVjLWRlM2QwYTQ1Y2RjNyIsImFjciI6IjAiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2xvY2FsaG9zdDo4MDAwIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW15cmVhbG0iLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwibXlyb2xlIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCIsInNpZCI6IjRmNjFkYzBjLTBkZDYtNGY4OS1hZGVjLWRlM2QwYTQ1Y2RjNyIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiVXNlckZpcnN0TmFtZSBVc2VyTGFzdE5hbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJrZXljbG9hayIsImdpdmVuX25hbWUiOiJVc2VyRmlyc3ROYW1lIiwiZmFtaWx5X25hbWUiOiJVc2VyTGFzdE5hbWUiLCJwaWN0dXJlIjoiaHR0cHM6Ly81OS5pbWcuYXZpdG8uc3QvYXZhdGFyL3NvY2lhbC8yNTZ4MjU2LzQ5MjUxMTMyNTkuanBnIiwiZW1haWwiOiJrZXljbG9ha0BrZXljbG9hay5vcmcifQ.ejh7opoSCZlq1rIcr5hqxZatUj0p334sdtxIO6HiMNOGiIhf7JQWqNObMajlSgj6eySV77IB_gkOg8upj8ueAoTeD890q6AryTwtIwYO02OkCBJkwyGj9z3zJnJi0sXigQPIbHAAF1v84fi9WX77WsUcEVc46gh5MBIJ4OXukGCCsANNgTBq3twq3BiSFBbCkLJTWmuzZ7FrjXl7jYfS3uTFiKChEk6cgtQqDd2DkK5_eF8a_uF9IJzVOSQp_JS657jFL3sbjJ1K8b9Z8qtpqtoQi0P_GDfeHV6zyTVk1rfjgky185kQtcqL1TpLjhzBSMd7QAckwUDQA8Yn8RiOEg",
  "expires_in": 300,
  "refresh_expires_in": 1766,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxNWM0NGVkZS0zZTYxLTQwMjItODQyNC0wNmM0YTA3MWM4NzcifQ.eyJleHAiOjE3MjUzMTE1MzYsImlhdCI6MTcyNTMwOTc3MCwianRpIjoiZjBhY2Y3NjUtY2RlMS00Y2U0LWIzNjQtNzQ5YjE1Njk2ZjJhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6Im9pZGMtcGxheWdyb3VuZCIsInNlc3Npb25fc3RhdGUiOiI0ZjYxZGMwYy0wZGQ2LTRmODktYWRlYy1kZTNkMGE0NWNkYzciLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiNGY2MWRjMGMtMGRkNi00Zjg5LWFkZWMtZGUzZDBhNDVjZGM3In0.xErkQUnCK6ulDKmbjLrwIMq1Z4oOxGR_50d3Dw0-yho",
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjUzMTAwNzAsImlhdCI6MTcyNTMwOTc3MCwiYXV0aF90aW1lIjoxNzI1MzA5MjkwLCJqdGkiOiI2NTEwOWU3ZS1mZjg0LTQ3YmItODRiOS0yNDY5NGIwZTQ2N2YiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJvaWRjLXBsYXlncm91bmQiLCJzdWIiOiI1YWIxNmE4Ni02OTc3LTQxZjgtYTUwYy03MzViODllY2Q4MTIiLCJ0eXAiOiJJRCIsImF6cCI6Im9pZGMtcGxheWdyb3VuZCIsInNlc3Npb25fc3RhdGUiOiI0ZjYxZGMwYy0wZGQ2LTRmODktYWRlYy1kZTNkMGE0NWNkYzciLCJhdF9oYXNoIjoiekx2TXFlX1dudGc4dGNOTGctTkZodyIsImFjciI6IjAiLCJzaWQiOiI0ZjYxZGMwYy0wZGQ2LTRmODktYWRlYy1kZTNkMGE0NWNkYzciLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlVzZXJGaXJzdE5hbWUgVXNlckxhc3ROYW1lIiwicHJlZmVycmVkX3VzZXJuYW1lIjoia2V5Y2xvYWsiLCJnaXZlbl9uYW1lIjoiVXNlckZpcnN0TmFtZSIsImZhbWlseV9uYW1lIjoiVXNlckxhc3ROYW1lIiwicGljdHVyZSI6Imh0dHBzOi8vNTkuaW1nLmF2aXRvLnN0L2F2YXRhci9zb2NpYWwvMjU2eDI1Ni80OTI1MTEzMjU5LmpwZyIsImVtYWlsIjoia2V5Y2xvYWtAa2V5Y2xvYWsub3JnIn0.Hd-8yQLHJnaOJhBSzYlx7XUvCcg0MW_nPqiyWxlb13IQTye5pJ1fgN19vYkuXCJKHSrUILGjYHhbIQAFY38WE5EjdqAII5THqAp1zUIK0rrm9oJx89i7LHE-c4D56UGIG7DJS5xC0EDkFTqCSD4elx5_Ho1ozltp52-5nczlU6WFWYaOJSbMHXwLRn1x1A7rdwGH8e67dR0_pjYHSbqIxCXIS0zI3fHbrJM-cKvSfxTeR0r1yO5CB3P-4JNJtozu6Uje_csikuueXS44_1h88D4e6GB6mCcKI7CHzYxfSqqVnWp9lWWIdjfU1PI8FOEreJngqFz-Pcvx7cQ6gzRk5w",
  "not-before-policy": 0,
  "session_state": "4f61dc0c-0dd6-4f89-adec-de3d0a45cdc7",
  "scope": "openid profile email"
}
```

где:

- `access_token` - токен доступа, являющийся подписанным JWT;
- `expires_in` - подсказка, когда срок действия токена истечет (полезна в случае, если токен является непрозрачным);
- `refresh_token` - токен обновления;
- `refresh_token_expires_in` - подсказка, когда срок действия токена обновления истечет (полезна в случае, если токен является
  непрозрачным);
- `token_type` - тип токена доступа (для Keycloak всегда имеет значение `bearer`);
- `id_token` - `ID Token` в `Base64 URL`-закодированном виде;
- `session_state` - идентификатор сессии, в которой пользователь подключался к Keycloak;
- `scope` - выданный `scope` (может отличаться от `scope`, запрошенного приложением в `Authentication Request`);

## ID Token, полученный после Token Response

Является подписанным JSON Web Token (JWT) и состоит из трех частей - `Header`, `Payload` и `Signature`.

#### Header:

`Base64 URL`-закодированный JSON.

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "GT_TX2zVJ0v3O6l4hsCyXT79d_bPSkZbrp8VvO2v2dY"
}
```

где:

- `alg` - алгоритм кодировки;
- `typ` - тип полезной нагрузки;
- `kid` - ID ключа, который использовался для подписания токена.

#### Payload:

`Base64 URL`-закодированный JSON.

```json
{
  "exp": 1725310070,
  "iat": 1725309770,
  "auth_time": 1725309290,
  "jti": "65109e7e-ff84-47bb-84b9-24694b0e467f",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oidc-playground",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "ID",
  "azp": "oidc-playground",
  "session_state": "4f61dc0c-0dd6-4f89-adec-de3d0a45cdc7",
  "at_hash": "zLvMqe_Wntg8tcNLg-NFhw",
  "acr": "0",
  "sid": "4f61dc0c-0dd6-4f89-adec-de3d0a45cdc7",
  "email_verified": true,
  "name": "UserFirstName UserLastName",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName",
  "family_name": "UserLastName",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak@keycloak.org"
}
```

где:

- `exp`: Unix-дата и время экспирации токена;
- `iat`: Unix-дата и время выпуска токена;
- `auth_time`: дата (и время?) последней аутентификации токена;
- `jti`: уникальный ID токена;
- `aud`: аудитория токена, содержащая `Relying Party` ("Доверяющую Сторону"), которая аутентифицирует пользователя;
- `azp`: сторона, для которой был выпущен токен;
- `sub`: уникальный ID аутентифицированного пользователя. Рекомендуется использовать именно ID пользователя, т.к. имя пользователя или email
  м.б. изменены со временем.

#### Signature:

```text
Hd-8yQLHJnaOJhBSzYlx7XUvCcg0MW_nPqiyWxlb13IQTye5pJ1fgN19vYkuXCJKHSrUILGjYHhbIQAFY38WE5EjdqAII5THqAp1zUIK0rrm9oJx89i7LHE-c4D56UGIG7DJS5xC0EDkFTqCSD4elx5_Ho1ozltp52-5nczlU6WFWYaOJSbMHXwLRn1x1A7rdwGH8e67dR0_pjYHSbqIxCXIS0zI3fHbrJM-cKvSfxTeR0r1yO5CB3P-4JNJtozu6Uje_csikuueXS44_1h88D4e6GB6mCcKI7CHzYxfSqqVnWp9lWWIdjfU1PI8FOEreJngqFz-Pcvx7cQ6gzRk5w
```

---

## Refresh Request

```text
http://localhost:8080/realms/myrealm/protocol/openid-connect/token

grant_type=refresh_token
refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxNWM0NGVkZS0zZTYxLTQwMjItODQyNC0wNmM0YTA3MWM4NzcifQ.eyJleHAiOjE3MjUzMTE1MzYsImlhdCI6MTcyNTMwOTc3MCwianRpIjoiZjBhY2Y3NjUtY2RlMS00Y2U0LWIzNjQtNzQ5YjE1Njk2ZjJhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6Im9pZGMtcGxheWdyb3VuZCIsInNlc3Npb25fc3RhdGUiOiI0ZjYxZGMwYy0wZGQ2LTRmODktYWRlYy1kZTNkMGE0NWNkYzciLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiNGY2MWRjMGMtMGRkNi00Zjg5LWFkZWMtZGUzZDBhNDVjZGM3In0.xErkQUnCK6ulDKmbjLrwIMq1Z4oOxGR_50d3Dw0-yho
client_id=oidc-playground
scope=openid
```

## Refresh Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjUzMTAyNTUsImlhdCI6MTcyNTMwOTk1NSwiYXV0aF90aW1lIjoxNzI1MzA5MjkwLCJqdGkiOiJhNWM2MWQxMS01YzZmLTQyYTctYWVkOS1iZDYzNDM3Mjk2MTQiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoib2lkYy1wbGF5Z3JvdW5kIiwic2Vzc2lvbl9zdGF0ZSI6IjRmNjFkYzBjLTBkZDYtNGY4OS1hZGVjLWRlM2QwYTQ1Y2RjNyIsImFjciI6IjAiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2xvY2FsaG9zdDo4MDAwIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW15cmVhbG0iLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwibXlyb2xlIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCIsInNpZCI6IjRmNjFkYzBjLTBkZDYtNGY4OS1hZGVjLWRlM2QwYTQ1Y2RjNyIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiVXNlckZpcnN0TmFtZSBVc2VyTGFzdE5hbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJrZXljbG9hayIsImdpdmVuX25hbWUiOiJVc2VyRmlyc3ROYW1lIiwiZmFtaWx5X25hbWUiOiJVc2VyTGFzdE5hbWUiLCJwaWN0dXJlIjoiaHR0cHM6Ly81OS5pbWcuYXZpdG8uc3QvYXZhdGFyL3NvY2lhbC8yNTZ4MjU2LzQ5MjUxMTMyNTkuanBnIiwiZW1haWwiOiJrZXljbG9ha0BrZXljbG9hay5vcmcifQ.dOLlBIlguBRIIkNgPrnXbco68Rrw7CZryoLdwIrtnYvgmUtLfxyuq4uEy-0LhqJgN_DkHgN-EnZ5lySyRI4qnAlh4lFyI0ZHn_8ywl9IV_Iablx2_rTP4_cRXHqe13QVgNo6ltQWiHtPbGXRNgq23bdE9cIuxZGFIOxxVzSgbyPXSxltLWn0bkAArPL-5lXvLlwdWo7ilW5111s3J8CK1rhArYvm5NIeMpfWvtu-A0nME2V3sWEsUVH5VMblLzlrPeJFlpQpYcA_HJh3l8cmKmZvpiOvB83H2xo8Okm8DgSuYzIX2IjtxFGH1uODoqU9_wF9wHND0e8NHBe1en2uCQ",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxNWM0NGVkZS0zZTYxLTQwMjItODQyNC0wNmM0YTA3MWM4NzcifQ.eyJleHAiOjE3MjUzMTE3NTUsImlhdCI6MTcyNTMwOTk1NSwianRpIjoiZTFmYWY0MTktMjFkMy00MWI0LWE5MDMtNmM5Y2YzNDJjZTNiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6Im9pZGMtcGxheWdyb3VuZCIsInNlc3Npb25fc3RhdGUiOiI0ZjYxZGMwYy0wZGQ2LTRmODktYWRlYy1kZTNkMGE0NWNkYzciLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiNGY2MWRjMGMtMGRkNi00Zjg5LWFkZWMtZGUzZDBhNDVjZGM3In0.KvPdDPy1jf6gnBgkcWvTPUOXofl5UepcYgvv65La66c",
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjUzMTAyNTUsImlhdCI6MTcyNTMwOTk1NSwiYXV0aF90aW1lIjoxNzI1MzA5MjkwLCJqdGkiOiIxNjIwYzg3Yy0xOWZlLTQ2ZDAtODgzMi0wYmNkOTVlNTIzYmEiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJvaWRjLXBsYXlncm91bmQiLCJzdWIiOiI1YWIxNmE4Ni02OTc3LTQxZjgtYTUwYy03MzViODllY2Q4MTIiLCJ0eXAiOiJJRCIsImF6cCI6Im9pZGMtcGxheWdyb3VuZCIsInNlc3Npb25fc3RhdGUiOiI0ZjYxZGMwYy0wZGQ2LTRmODktYWRlYy1kZTNkMGE0NWNkYzciLCJhdF9oYXNoIjoiRjJkcXFhNEJiUFA1UE9hbzJGSnpXQSIsImFjciI6IjAiLCJzaWQiOiI0ZjYxZGMwYy0wZGQ2LTRmODktYWRlYy1kZTNkMGE0NWNkYzciLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlVzZXJGaXJzdE5hbWUgVXNlckxhc3ROYW1lIiwicHJlZmVycmVkX3VzZXJuYW1lIjoia2V5Y2xvYWsiLCJnaXZlbl9uYW1lIjoiVXNlckZpcnN0TmFtZSIsImZhbWlseV9uYW1lIjoiVXNlckxhc3ROYW1lIiwicGljdHVyZSI6Imh0dHBzOi8vNTkuaW1nLmF2aXRvLnN0L2F2YXRhci9zb2NpYWwvMjU2eDI1Ni80OTI1MTEzMjU5LmpwZyIsImVtYWlsIjoia2V5Y2xvYWtAa2V5Y2xvYWsub3JnIn0.iHYeVoEXQZkRJAFKCOBzhto-GWP3Sgt1ovE96wY78rBmP7fyvjpwEi0T_0KNfN2kKFmRbOyczX850bTF4C66GDPTpBgcdoNZKTZVH00qA8usvakHeLEgUKue4Ol7vSldcO-veRNOlMhixS-B4MfgoveEwVLNfyxB4E5XuC1AWWzEcELOO5L3Yl22IftgQblavzwKzFN-GayYbmXjfJ8T1XizFVGruY0f7Sxhvg2FdDX1A3lbRhT9uL4lTAOB2_MLsD2JRHoQ353YrChaPoo3IEvikQi9q8mw0feqHKA7QDZT3K19gZjxU3qSHdnYRCPkYfIxBXQS5Y-iRgpGsxddSg",
  "not-before-policy": 0,
  "session_state": "4f61dc0c-0dd6-4f89-adec-de3d0a45cdc7",
  "scope": "openid profile email"
}
```

Этот `Refresh Response` аналогичен тому, что был получен после первого Token Request, за исключением нового токена, новых дат и того,
что `Refresh Token` отличается от первоначального по причине:

- **ротация ключей** - Keycloak может менять свои ключи подписи и полагается на получение клиентами новых токенов обновления, подписанных
  новыми ключами.
- **простой сеанса** - у клиента (или сеанса) токен обновления может иметь более короткий срок действия, чем связанный сеанс;
- **утечка токена обновления** - для исключения утечки токенов обновления Keycloak не позволит повторно использовать токены обновления (по
  умолчанию в Keycloak эта функция отключена).

## ID Token, полученный после Refresh Response

```json
{
  "exp": 1725310255,
  "iat": 1725309955,
  "auth_time": 1725309290,
  "jti": "1620c87c-19fe-46d0-8832-0bcd95e523ba",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oidc-playground",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "ID",
  "azp": "oidc-playground",
  "session_state": "4f61dc0c-0dd6-4f89-adec-de3d0a45cdc7",
  "at_hash": "F2dqqa4BbPP5POao2FJzWA",
  "acr": "0",
  "sid": "4f61dc0c-0dd6-4f89-adec-de3d0a45cdc7",
  "email_verified": true,
  "name": "UserFirstName UserLastName",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName",
  "family_name": "UserLastName",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak@keycloak.org"
}
```

---

# Добавление пользовательского свойства

1. Зайти в административную консоль Keycloak на закладку "Users":
   ![01_keycloak_users.png](img/100_keycloak_users.png)

2. Зайти в настройки пользователя, перейти на закладку "Attributes", добавить желаемый атрибут (`myattribute`) и сохранить:
   ![02_keycloak_user_keycloak.png](img/110_keycloak_user_keycloak.png)

3. Создать клиентскую область видимости (`Scope`). Для этого перейти в меню "Client scopes" и на закладке "Settings" задать имя области
   видимости 'myscope' и сохранить:

![03_keycloak_clientScope_myscope.png](img/120_keycloak_clientScope_myscope.png)

> Клиентский scope позволяет создавать повторно используемые группы параметров, которые добавляются в токен выпускаемый клиенту.

4. Создать сопоставление (`mapper`). Для этого перейти на закладку "Mappers", нажать кнопку "Add mapper" и выбрать "By configuration":

![04_keycloak_clientScope_myscope_mapper_byConfiguration.png](img/130_keycloak_clientScope_myscope_mapper_byConfiguration.png)

В меню выбрать пункт "User Attribute":
![04_keycloak_clientScope_myscope_mapper_byConfiguration_userAttribute.png](img/131_keycloak_clientScope_myscope_mapper_byConfiguration_userAttribute.png)

Далее, в параметрах сопоставления указать:

- **Name**: `myattribute`
- **User Attribute**: `myattribute`
- **Token Claim Name**: `myattribute`
- **Claim JSON Type**: `String`
- **Признак "Add to ID token"**: `ON`

И сохранить:

![04_keycloak_clientScope_myscope_mapper_myattribute.png](img/132_keycloak_clientScope_myscope_mapper_myattribute.png)

5. Добавить клиенту созданную область видимости (`scope`) в качестве опциональной. Для этого перейти в меню "Clients", выбрать требуемого
   клиента (`oidc-playground`) и на закладке "Client scopes" нажать кнопку "Add client scope", после чего в открывшемся меню пометить
   флажком требуемую область видимости (`myscope`) после чего нажать кнопку "Add" и выбрать вариант "Optional":

![05_keycloak_client_oidc-playground_myscope.png](img/140_keycloak_client_oidc-playground_myscope.png)

**Т.о. опциональный `scope` был добавлен клиенту.**

> "Опциональная" область видимости означает, что клиент должен запрашивать её явно.
>
> "Дефолтная" область видимости добавляется в результат запроса всегда.

---

# Добавление ролей в "ID Token"

По умолчанию роли в `ID Token` не добавляются.

1. В меню "Client scopes" выбрать область видимости `roles`:
   ![200_client_scopes.png](img/200_client_scopes.png)

2. В настройках области видимости `roles` перейти на закладку "Mappers" и выбрать сопоставление `realm roles`:
   ![210_client_scopes_roles.png](img/210_client_scopes_roles.png)

3. В настройках сопоставления `realm roles` включить признак "Add to ID token" и сохранить:
   ![220_client_scopes_roles_realmRoles.png](img/220_client_scopes_roles_realmRoles.png)

Теперь в составе `ID Token` в разделе `realm_access.roles` будет присутствовать массив ролей:

<table>
<tr align="center"><td><b>"ID Token" без ролей</b></td><td><b>"ID Token" с ролями</b></td></tr>
<tr  valign="top"><td>

```json
{
  "exp": 1725363113,
  "iat": 1725362813,
  "auth_time": 1725361403,
  "jti": "11ba7c27-1f8c-4b44-8aaf-3ffb6957bf8a",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oidc-playground",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "ID",
  "azp": "oidc-playground",
  "session_state": "13b56ec9-3cef-4461-935c-830edcc057e5",
  "at_hash": "qQyq1-skUE1nGCB0lqA4Yw",
  "acr": "0",
  "sid": "13b56ec9-3cef-4461-935c-830edcc057e5",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "myattribute": "myvalue",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

</td>
<td>

```json
{
  "exp": 1725363121,
  "iat": 1725362821,
  "auth_time": 1725361403,
  "jti": "28024812-c22c-4313-859d-0fb72d5afe81",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oidc-playground",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "ID",
  "azp": "oidc-playground",
  "session_state": "13b56ec9-3cef-4461-935c-830edcc057e5",
  "at_hash": "MGVyQlqqIUYZUX53vy_fRw",
  "acr": "0",
  "sid": "13b56ec9-3cef-4461-935c-830edcc057e5",
  "email_verified": true,
  "realm_access": {
    "roles": [
      "default-roles-myrealm",
      "offline_access",
      "uma_authorization",
      "myrole"
    ]
  },
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "myattribute": "myvalue",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

</td></tr></table>

> По умолчанию все роли добавляются всем клиентам, что не очень критично для `ID Token`, используемого для аутентификации пользователя у
> конкретного клиента, но нежелательно для `Access Token`, используемого для доступа к другим сервисам.

---

# Получение UserInfo

## UserInfo Request

```text
http://localhost:8080/realms/myrealm/protocol/openid-connect/userinfo

Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjUzNjY0MjIsImlhdCI6MTcyNTM2NjEyMiwiYXV0aF90aW1lIjoxNzI1MzY2MTE0LCJqdGkiOiJkYTI3MjkyZi02ZmNiLTRlZTAtOWM5ZC1iNjk0MjJiNTc3NjYiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoib2lkYy1wbGF5Z3JvdW5kIiwic2Vzc2lvbl9zdGF0ZSI6ImVjZjZlMTg3LWJjYzMtNDUyNi05ZWU2LTUzOGE0MzNlMWJiNSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2xvY2FsaG9zdDo4MDAwIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW15cmVhbG0iLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwibXlyb2xlIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgbXlzY29wZSBwcm9maWxlIGVtYWlsIiwic2lkIjoiZWNmNmUxODctYmNjMy00NTI2LTllZTYtNTM4YTQzM2UxYmI1IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJVc2VyRmlyc3ROYW1lMiBVc2VyTGFzdE5hbWUyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoia2V5Y2xvYWsiLCJnaXZlbl9uYW1lIjoiVXNlckZpcnN0TmFtZTIiLCJmYW1pbHlfbmFtZSI6IlVzZXJMYXN0TmFtZTIiLCJteWF0dHJpYnV0ZSI6Im15dmFsdWUiLCJwaWN0dXJlIjoiaHR0cHM6Ly81OS5pbWcuYXZpdG8uc3QvYXZhdGFyL3NvY2lhbC8yNTZ4MjU2LzQ5MjUxMTMyNTkuanBnIiwiZW1haWwiOiJrZXljbG9hazJAa2V5Y2xvYWsub3JnIn0.ONVLdu3mj5ABD6iffD7N5QewCQceOHQsB-aq20CZ2izCViL1hLySJlumgeKbv9gr84MfjDF8ldaUG6rUQvGoqZuMIhLimkD4T9QJk1QrLNjUA3md3MolR-8Sv5nTxRi2c2-VEYJHu0vCGLAPKHvGmYZJImYBZqVhPW2VURDQnIhqdRiH2lHZ2a51qV1YgnkuBVcnm-ixckyzXhC9izd11R32pg5zDweSaDIyRSF4E4PpoBaBEePSDWBICH4O7cmT4L_Uykcak27fADQDDD_XK6YwnxhmySlO_jMXSkeNwyO7zHURa1-QPOOr-HVSKsJAobXzcnrStKyjrxQdTj4-_Q
```

## UserInfo Response

Содержит только пользовательские аттрибуты:

```json
{
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "myattribute": "myvalue",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

Существует возможность контролировать, какая информация возвращается клиенту, вызывающему точку доступа `UserInfo` (но не клиенту
имеющему `Access Token`).

Как следствие, можно обратиться к разным ресурсным серверам, используя один и тот же `Access Token`, но получить от них разную информацию в
соответствии с их настройками.

### Настройка информации, возвращаемой UserInfo

1. Добавить сопоставление непосредственно клиенту. Для этого в меню "Clients" выбираем клиента (здесь - `oidc-playground`):
   ![300_client.png](img/300_client.png)

2. В настройках клиента на закладке "Client scopes" заходим в настройки области (здесь - `oidc-playground-dedicated`):
   ![310_client_oidc-playground.png](img/310_client_oidc-playground.png)

3. Жмем кнопку "Configure a new mapper" (или "Add mapper" -> "By configuration" если сопоставления уже есть) и выбираем "Hardcoded claim":

![320_client_oidc-playground_hardcodedClaim.png](img/320_client_oidc-playground_hardcodedClaim.png)

4. В параметрах сопоставления указать:

- **Name**: `myotherclaim`
- **User Attribute**: `myotherclaim`
- **Token Claim Name**: `My Other Claim`
- **Claim JSON Type**: `String`
- **Признак "Add to userinfo"**: `ON`

![330_client_oidc-playground_myOtherClaim.png](img/330_client_oidc-playground_myOtherClaim.png)

Теперь новое свойство `myotherclaim` отображается в информации о пользователе:

<table>
<tr align="center"><td><b>Исходный вариант UserInfo</b></td><td><b>UserInfo с добавленным свойством "myotherclaim"</b></td></tr>
<tr valign="top"><td>

```json
{
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "myattribute": "myvalue",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

</td><td>

```json
{
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "myotherclaim": "My Other Claim",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "myattribute": "myvalue",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

</td></tr>
</table>

> UserInfo можно получить только с помощью `Access Token`, полученного через OIDC. Т.е. в `Authentication Request` в поле `scope` должно
> присутствовать значение `openid`!

---

# Logout (SSO, Single-Sign Out)

При инициализации логаута приложение перенаправляет пользователя на точку доступа `Keycloak End Session`, зарегистрированной в метаданных
`OpenID Provider` как `end_session_endpoint` и принимающей следующие параметры:

- `id_token_hint` - ранее выданный идентификационный токен. Используется Keycloak для идентификации клиента или пользователя, выходящих из
  системы, а также сессии, из которого клиент хочет выйти;
- `post_logout_redirect_uri` - Keycloak перенаправит клиента на этот адрес после логаута;
- `state` - позволяет клиента передавать состояние между запросом на логаут и редиректом. Keycloak просто передаёт этот параметр при
  редиректе на клиента;
- `ui_locales` - подсказка Keycloak, какая локаль должна использоваться для экрана логина.

Когда Keycloak получает запрос на логаут, то он в этой же сессии уведомляет других клиентов о логауте и **инвалидирует сессию, эффективно
инвалидируя все токены**.

### Подход 1: Использование ID и срока действия `Access Token`

Самым простым и надежным механизмом приложению обнаружить логаут это просто использовать тот факт, что `ID` и `Access Token` являются
короткоживущими. Когда Keycloak инвалидирует сессию при логауте, то `Refresh Token` уже не м.б. использован для получения новых токенов.

Недостаток такого подхода в том, что с момента выхода пользователя из системы и до логаута всех приложений может пройти несколько минут (
хотя зачастую этого достаточно).

Это также хорошая стратегия для общедоступных клиентов. Поскольку они обычно не предоставляют услуги напрямую, а используют токен доступа
для вызова других служб, они быстро поймут, что сеанс больше недействителен.

В случаях долгоживущих токенов рекомендуется вызывать точку доступа `Token Introspection` для периодической проверки действительности
токена.

### Подход 2: Использование OIDC Session Management

С помощью `OIDC Session Management` приложение может определить, был ли завершен сеанс, без запросов к Keycloak или от Keycloak.

Это работает путем мониторинга состояния специального сессионного **cookie**, которым управляет Keycloak.

Но т.к. приложение и Keycloak обычно размещаются в разных доменах, приложение не может прочитать этот **cookie** напрямую. Вместо этого,
скрытый HTML-тег `<iframe>` загружает специальную страницу Keycloak, которая отслеживает значение `cookie` и, при обнаружении изменения
состояния сеанса, отправляет приложению специальное событие.

Это эффективная стратегия, особенно если приложение в данный момент открыто. Но даже если приложение закрыто, то это не означает, что
приложение не обнаружит логаута до момента своего открытия.

Например, если сервер был скомпроментирован, то атакующий может предотвратить работу сессионного `<iframe>`, оставляя таким образом сессию
открытой. Но это легко устраняется если, например, держать сессию приложения открытой только пока приложение открыто.

`Keycloak JavaScript Adapter` именно так и поступает, просто храня токены в окне. Кроме того, ситуация смягчается за счет короткого срока
жизни токенов.

Но, к сожалению, приходится отказываться от использования `OIDC Session Management`, т.к. многие браузеры начали блокировать доступ к
стороннему контенту, не позволяя сессионному `<iframe>` получить доступ к `cookie` сеанса.

### Подход 3: Использование OIDC Back-Channel Logout

При использовании `OIDC Back-Channel Logout` приложение регистрирует точку доступа для получения события выхода из системы.

Когда логаут инициируется с помощью Keycloak, то он отправляет `Logout Token` всем приложениям сессии, для которых зарегистрирована точка
доступа логаута.

`Logout Token` аналогичен `ID Token` и представляет собой подписанный JWT. При получении `Logout Token` приложение проверяет подпись и
закрывает сессию приложения, ассоциированную с ID сессии Keycloak.

Для серверных приложений использование `OIDC Back-Channel Logout` вполне эффективно. Однако для кластерных приложений с закреплением сеансов
всё сложнее. Распространенным подходом к масштабированию `stateful`-приложений является распределение сессии между экземплярами приложения,
но нет
никакой гарантии, что запрос от Keycloak на выход из системы будет отправлен именно тому экземпляру приложения, который фактически хранит
сессию приложения.

Настройка балансировщика нагрузки для маршрутизации `Logout Request` в правильный сеанс является непростой задачей, поэтому обычно это
то, что работает на уровне приложения.

Для серверных `stateless`-приложений `Logout Request` также сложно обработать, поскольку в этом случае сессия обычно
сохраняется в `cookie`. Здесь приложению приходится запоминать `Logout Request` либо до следующего запроса к приложению в данном сеансе,
либо до истечения срока действия сессии приложения.

### Подход 4: Использование OIDC Front-Channel Logout

`OpenID Connect Front-Channel Logout` использует скрытый `<iframe>` для каждого приложения, имеющего зарегистрированную точку
доступа `Front-Channel Logout` на странице логаута OpenID-провайдера.

Теоретически это был бы хороший способ выйти из серверного `stateless`-приложения или из клиентского приложения. Однако на практике это
может быть ненадежно т.к. не существует эффективного способа для `OpenID`-провайдера обнаружить факт успешного выхода из приложения.

Кроме того, подход `OIDC Front-Channel Logout` страдает от того, что браузеры блокируют сторонний контент, а это означает, что, когда
`OpenID`-провайдер открывает в `<iframe>` точку доступа логаута, то нет доступа ни к каким `cookie` уровня приложения и у приложения нет
доступа к текущей сессии аутентификации.

## Итоги

Таким образом, самым простым подходом является просто **полагаться на короткие сессии приложения и истечение срока действия токена**.
Поскольку Keycloak будет удерживать пользователя в системе, то можно эффективно использовать короткоживующие сессии приложения, не требуя от
пользователей частой повторной аутентификации.

В прочих случаях, или там, где **выход из системы должен быть мгновенным**, следует использовать `OIDC Back-Channel Logout`.

---
