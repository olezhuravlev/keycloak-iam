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

![auth_code_flow_frontend.jpg](img/200_auth_code_flow_frontend.jpg)

#### Токены, генерируемые Keycloak:

<table>
<tr align="center">
<td> <b>ID Token</b> </td> <td> <b>Access Token</b> </td>
</tr>
<tr valign="top">
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

![auth_code_flow_backend.jpg](img/210_auth_code_flow_backend.jpg)

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

![oauth2_code_flow.jpg](img/300_oauth2_code_flow.jpg)

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
  доступа `Token Introspection` позволяет клиенту получить информацию об `Access Tokens` не зная его формата;
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
Кроме того, его использование избавляет ресурсные серверы от необходимости выполнять запросы к точкам доступа
Keycloak `OAuth 2.0 Token Introspection`, или `OIDC UserInfo`.

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

#### [Будут возвращены URL](#keycloak-urls):

| № | Точка доступа                         | URL                                                 | Назначение                                                                                   |
|---|---------------------------------------|-----------------------------------------------------|----------------------------------------------------------------------------------------------|
|   | Issuer URL                            | http://localhost:8080/realms/{REALM_NAME}           | Корневой URL Keycloak вернет публичный ключ, а также URL `token-service` и `account-service` |
|   | OIDC Provider Configuration           | /.well-known/openid-configuration                   |                                                                                              |
|   | Registration Endpoint                 | /clients-registrations/openid-connect               |                                                                                              |
| 1 | Authorization Endpoint                | `/protocol/openid-connect`/auth                     | Обращение `Authentication Request` за авторизацией                                           |
|   | Device Authorization Endpoint         | `/protocol/openid-connect`/auth/device              |                                                                                              |
| 2 | Token Endpoint                        | `/protocol/openid-connect`/token                    | URL для `Token Request` и `Refresh Request` для обмена `Authorization Code` на токены        |
|   | End Session Endpoint                  | `/protocol/openid-connect`/logout                   | URL для `Logout Request`                                                                     |
|   | JWKS URI                              | `/protocol/openid-connect`/certs                    | URL для получения публичных ключей Keycloak                                                  |
|   | Backchannel Authentication Endpoint   | `/protocol/openid-connect`/ext/ciba/auth            |                                                                                              |
|   | Pushed Authorization Request Endpoint | `/protocol/openid-connect`/ext/par/request          |                                                                                              |
|   | Check Session IFrame                  | `/protocol/openid-connect`/login-status-iframe.html |                                                                                              |
|   | Revocation Endpoint                   | `/protocol/openid-connect`/revoke                   |                                                                                              |
|   | Introspection Endpoint                | `/protocol/openid-connect`/token/introspect         | URL для верификации токена доступа                                                           |
|   | Userinfo Endpoint                     | `/protocol/openid-connect`/userinfo                 | URL для получения информации об аутентифицированном пользователе (`UserInfo Request`)        |

Кроме того, возвращаются:

- `grant_types_supported`: Список поддерживаемых типов грантов:
    - `authorization_code` -
- `response_types_supported`: Список поддерживаемых типов ответов:
    - `code` - приложение желает получить авторизационный код (`Authorization Code`) от Keycloak;
    - `token` -

> Авторизационнй код имеет вид:
>
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

![openid_connect_auth_code_flow.jpg](img/400_openid_connect_auth_code_flow.jpg)</td>
<td>

![openid_connect_auth_code_flow_2.jpg](img/410_openid_connect_auth_code_flow_2.jpg)</td>
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

### ID Token, полученный после Token Response

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

### Refresh Request

```text
http://localhost:8080/realms/myrealm/protocol/openid-connect/token

grant_type=refresh_token
refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxNWM0NGVkZS0zZTYxLTQwMjItODQyNC0wNmM0YTA3MWM4NzcifQ.eyJleHAiOjE3MjUzMTE1MzYsImlhdCI6MTcyNTMwOTc3MCwianRpIjoiZjBhY2Y3NjUtY2RlMS00Y2U0LWIzNjQtNzQ5YjE1Njk2ZjJhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6Im9pZGMtcGxheWdyb3VuZCIsInNlc3Npb25fc3RhdGUiOiI0ZjYxZGMwYy0wZGQ2LTRmODktYWRlYy1kZTNkMGE0NWNkYzciLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiNGY2MWRjMGMtMGRkNi00Zjg5LWFkZWMtZGUzZDBhNDVjZGM3In0.xErkQUnCK6ulDKmbjLrwIMq1Z4oOxGR_50d3Dw0-yho
client_id=oidc-playground
scope=openid
```

### Refresh Response

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

### ID Token, полученный после Refresh Response

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

## Добавление пользовательского свойства

1. Зайти в административную консоль Keycloak на закладку "Users":

![keycloak_users.png](img/420_keycloak_users.png)

2. Зайти в настройки пользователя, перейти на закладку "Attributes", добавить желаемый атрибут (`myattribute`) и сохранить:

![keycloak_user_keycloak.png](img/421_keycloak_user_keycloak.png)

3. Создать клиентскую область видимости (`Scope`). Для этого перейти в меню "Client scopes" и на закладке "Settings" задать имя области
   видимости 'myscope' и сохранить:

![keycloak_clientScope_myscope.png](img/422_keycloak_clientScope_myscope.png)

> Клиентский scope позволяет создавать повторно используемые группы параметров, которые добавляются в токен выпускаемый клиенту.

4. Создать сопоставление (`mapper`). Для этого перейти на закладку "Mappers", нажать кнопку "Add mapper" и выбрать "By configuration":

![keycloak_clientScope_myscope_mapper_byConfiguration.png](img/423_keycloak_clientScope_myscope_mapper_byConfiguration.png)

В меню выбрать пункт "User Attribute":

![keycloak_clientScope_myscope_mapper_byConfiguration_userAttribute.png](img/424_keycloak_clientScope_myscope_mapper_byConfiguration_userAttribute.png)

Далее, в параметрах сопоставления указать:

- **Name**: `myattribute`
- **User Attribute**: `myattribute`
- **Token Claim Name**: `myattribute`
- **Claim JSON Type**: `String`
- **Признак "Add to ID token"**: `ON`

И сохранить:

![keycloak_clientScope_myscope_mapper_myattribute.png](img/425_keycloak_clientScope_myscope_mapper_myattribute.png)

5. Добавить клиенту созданную область видимости (`scope`) в качестве опциональной. Для этого перейти в меню "Clients", выбрать требуемого
   клиента (`oidc-playground`) и на закладке "Client scopes" нажать кнопку "Add client scope", после чего в открывшемся меню пометить
   флажком требуемую область видимости (`myscope`) после чего нажать кнопку "Add" и выбрать вариант "Optional":

![keycloak_client_oidc-playground_myscope.png](img/426_keycloak_client_oidc-playground_myscope.png)

**Т.о. опциональный `scope` был добавлен клиенту.**

> "Опциональная" область видимости означает, что клиент должен запрашивать её явно.
>
> "Дефолтная" область видимости добавляется в результат запроса всегда.

---

## Добавление ролей в "ID Token"

По умолчанию роли в `ID Token` не добавляются.

1. В меню "Client scopes" выбрать область видимости `roles`:

![client_scopes.png](img/430_client_scopes.png)

2. В настройках области видимости `roles` перейти на закладку "Mappers" и выбрать сопоставление `realm roles`:

![client_scopes_roles.png](img/431_client_scopes_roles.png)

3. В настройках сопоставления `realm roles` включить признак "Add to ID token" и сохранить:

![client_scopes_roles_realmRoles.png](img/432_client_scopes_roles_realmRoles.png)

Теперь в составе `ID Token` в разделе `realm_access.roles` будет присутствовать массив ролей:

<table>
<tr align="center"><td><b>"ID Token" без ролей</b></td><td><b>"ID Token" с ролями</b></td></tr>
<tr valign="top"><td>

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

## Получение UserInfo

### UserInfo Request

```text
http://localhost:8080/realms/myrealm/protocol/openid-connect/userinfo

Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjUzNjY0MjIsImlhdCI6MTcyNTM2NjEyMiwiYXV0aF90aW1lIjoxNzI1MzY2MTE0LCJqdGkiOiJkYTI3MjkyZi02ZmNiLTRlZTAtOWM5ZC1iNjk0MjJiNTc3NjYiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoib2lkYy1wbGF5Z3JvdW5kIiwic2Vzc2lvbl9zdGF0ZSI6ImVjZjZlMTg3LWJjYzMtNDUyNi05ZWU2LTUzOGE0MzNlMWJiNSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2xvY2FsaG9zdDo4MDAwIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW15cmVhbG0iLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwibXlyb2xlIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgbXlzY29wZSBwcm9maWxlIGVtYWlsIiwic2lkIjoiZWNmNmUxODctYmNjMy00NTI2LTllZTYtNTM4YTQzM2UxYmI1IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJVc2VyRmlyc3ROYW1lMiBVc2VyTGFzdE5hbWUyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoia2V5Y2xvYWsiLCJnaXZlbl9uYW1lIjoiVXNlckZpcnN0TmFtZTIiLCJmYW1pbHlfbmFtZSI6IlVzZXJMYXN0TmFtZTIiLCJteWF0dHJpYnV0ZSI6Im15dmFsdWUiLCJwaWN0dXJlIjoiaHR0cHM6Ly81OS5pbWcuYXZpdG8uc3QvYXZhdGFyL3NvY2lhbC8yNTZ4MjU2LzQ5MjUxMTMyNTkuanBnIiwiZW1haWwiOiJrZXljbG9hazJAa2V5Y2xvYWsub3JnIn0.ONVLdu3mj5ABD6iffD7N5QewCQceOHQsB-aq20CZ2izCViL1hLySJlumgeKbv9gr84MfjDF8ldaUG6rUQvGoqZuMIhLimkD4T9QJk1QrLNjUA3md3MolR-8Sv5nTxRi2c2-VEYJHu0vCGLAPKHvGmYZJImYBZqVhPW2VURDQnIhqdRiH2lHZ2a51qV1YgnkuBVcnm-ixckyzXhC9izd11R32pg5zDweSaDIyRSF4E4PpoBaBEePSDWBICH4O7cmT4L_Uykcak27fADQDDD_XK6YwnxhmySlO_jMXSkeNwyO7zHURa1-QPOOr-HVSKsJAobXzcnrStKyjrxQdTj4-_Q
```

### UserInfo Response

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

![client.png](img/440_client.png)

2. В настройках клиента на закладке "Client scopes" заходим в настройки области (здесь - `oidc-playground-dedicated`):

![client_oidc-playground.png](img/441_client_oidc-playground.png)

3. Жмем кнопку "Configure a new mapper" (или "Add mapper" -> "By configuration" если сопоставления уже есть) и выбираем "Hardcoded claim":

![client_oidc-playground_hardcodedClaim.png](img/442_client_oidc-playground_hardcodedClaim.png)

4. В параметрах сопоставления указать:

- **Name**: `myotherclaim`
- **User Attribute**: `myotherclaim`
- **Token Claim Name**: `My Other Claim`
- **Claim JSON Type**: `String`
- **Признак "Add to userinfo"**: `ON`

![client_oidc-playground_myOtherClaim.png](img/443_client_oidc-playground_myOtherClaim.png)

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

## Logout (SSO, Single-Sign Out)

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

---

# 5. Авторизация доступа с помощью OAuth 2.0

![510_obtain_oauth20_token.png](img/510_obtain_oauth20_token.png)

1. Пользователь предпринимает действие, требующее отправки запроса к внешнему REST API;
2. Приложение создаёт `Authorization Request`, размещая в нём набор параметров;
3. Приложение отправляет `Authorization Request` с кодом `302` перенаправляя браузер пользователя на `Authorization Endpoint` Keycloak;
4. Браузер пользователя переходит на `Authorization Endpoint` Keycloak с параметрами, содержащимися в `Authorization Endpoint`;
5. Если пользователь еще не аутентифицирован, то Keycloak отправляет ему страницу логина;
6. Если приложению требуется согласие пользователя на доступ к REST API (т.е. приложение хочет действовать от имени пользователя), то
   пользователю отображается страница, на которой ему предлагается согласиться или отказаться от предоставления такого доступа;
7. Keycloak передаёт приложению авторизационный код;
8. Приложение отправляет `Token Request` с целью обмена полученного авторизационного кода на два токена - `Access Token` и `Refresh Token`;
9. Приложение использует полученный `Access Token` для вызова REST API.

---

### Токен доступа

#### Header:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "GT_TX2zVJ0v3O6l4hsCyXT79d_bPSkZbrp8VvO2v2dY"
}
```

#### Payload:

```json
{
  "exp": 1726780390,
  "iat": 1726780090,
  "auth_time": 1726779738,
  "jti": "e9a38cef-f965-4d0b-bf0c-c99cddc80f3a",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "account",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "Bearer",
  "azp": "oauth-playground",
  "session_state": "31634ecf-5e65-4059-a720-645e76c41dbf",
  "acr": "0",
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
  "scope": "profile email",
  "sid": "31634ecf-5e65-4059-a720-645e76c41dbf",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

**где:**

- `aud`: список сервисов, для отправки в которые предназначен данный токен;
- `realm_access`: список **глобальных ролей**, к которым токен предоставляет доступ. Является объединением ролей, назначенных пользователю,
  и ролей к которым приложению разрешен доступ;
- `resource_access`: список **клиентских ролей**, к которым токен предоставляет доступ;
- `scope`: область видимости, включенная в `Access token`.

#### Signature:

```text
oA3QCc5wP8ZTRyG3tpHpzg0EVXWH6xee2StZtX_bumU_iJTHB5eoXFvnAOlFpRHk6brGlgTFzPm6cwN8cMxv6nB-k3jCx-1trLmwoejAzTV9xLBuHrBhReDIaTh2T1yUwZDHQ3xQdBkuSSevo7CEQjPTDsFbK7R6H1U1uyaPMlHIdCVNQLCPWhvlWgNOR7vfM2t7Z6oXyWa8FWnBTb6oOaW1_4NkUO-ScxOuMQDz9wDqMe6xNLivsh_DDw_GLw4aoTzso2a6I9QqUdbWZ6uVqMLVmLKLuVlc985S35Z7MPqjfBgfMJ7dnNlMB7hD8YwA8dMIHLCESmY9_Ivoipq1Gg
```

#### Encoded:

```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjY3ODAzOTAsImlhdCI6MTcyNjc4MDA5MCwiYXV0aF90aW1lIjoxNzI2Nzc5NzM4LCJqdGkiOiJlOWEzOGNlZi1mOTY1LTRkMGItYmYwYy1jOTljZGRjODBmM2EiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoib2F1dGgtcGxheWdyb3VuZCIsInNlc3Npb25fc3RhdGUiOiIzMTYzNGVjZi01ZTY1LTQwNTktYTcyMC02NDVlNzZjNDFkYmYiLCJhY3IiOiIwIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1teXJlYWxtIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiIsIm15cm9sZSJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjMxNjM0ZWNmLTVlNjUtNDA1OS1hNzIwLTY0NWU3NmM0MWRiZiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiVXNlckZpcnN0TmFtZTIgVXNlckxhc3ROYW1lMiIsInByZWZlcnJlZF91c2VybmFtZSI6ImtleWNsb2FrIiwiZ2l2ZW5fbmFtZSI6IlVzZXJGaXJzdE5hbWUyIiwiZmFtaWx5X25hbWUiOiJVc2VyTGFzdE5hbWUyIiwicGljdHVyZSI6Imh0dHBzOi8vNTkuaW1nLmF2aXRvLnN0L2F2YXRhci9zb2NpYWwvMjU2eDI1Ni80OTI1MTEzMjU5LmpwZyIsImVtYWlsIjoia2V5Y2xvYWsyQGtleWNsb2FrLm9yZyJ9.oA3QCc5wP8ZTRyG3tpHpzg0EVXWH6xee2StZtX_bumU_iJTHB5eoXFvnAOlFpRHk6brGlgTFzPm6cwN8cMxv6nB-k3jCx-1trLmwoejAzTV9xLBuHrBhReDIaTh2T1yUwZDHQ3xQdBkuSSevo7CEQjPTDsFbK7R6H1U1uyaPMlHIdCVNQLCPWhvlWgNOR7vfM2t7Z6oXyWa8FWnBTb6oOaW1_4NkUO-ScxOuMQDz9wDqMe6xNLivsh_DDw_GLw4aoTzso2a6I9QqUdbWZ6uVqMLVmLKLuVlc985S35Z7MPqjfBgfMJ7dnNlMB7hD8YwA8dMIHLCESmY9_Ivoipq1Gg
```

### Отзыв `OAuth2.0`-разрешений

Производится через консоль аккаунта, которая расположена по адресу: `{server-root}/realms/{realm-name}/account`:

```bash
http://localhost:8080/realms/myrealm/account
```

Отзыв выполняется в разделе `Applications` по кнопке `Remove access` соответствующего приложения.

---

## Три стратегии ограничения доступа у `Access Token`

1. **Audience** - указывается список поставщиков ресурсов, которые могут принять данный `Access Token`;
2. **Roles** - путём выдачи клиенту ролей возможно задать, к каким ролям приложение будет иметь доступ, выступая от имени этого клиента;
3. **Scope** - клиенту назначены определенные области видимости и приложение имеет доступ только к указанному списку областей. Кроме этого,
   когда приложению требуется согласие пользователя на доступ, то пользователь должен выдать доступ и к области видимости.

---

### 1. Стратегия ограничения доступа `Audience`

Изначально токен доступа, выданный фронтовой части приложения, не включает `backend` в `audience`. Но секретные данные всё равно выдаются,
потому что в параметре `verify-token-audience` файла [keycloak.json](applications/ch5/backend/keycloak.json) установлено значение `false`.
Поменяем его на `true` и после перезапуска бэкенд-приложения секретная часть уже не выдаётся (`Access denied`) по причине того, что токен
доступа теперь отвергается.

Добавим `audience` вручную через `protocol mapper`. Для этого создадим нового клиента с именем `oauth-playground`:

![520_audience_1.png](img/520_audience_1.png)

Т.к. клиент `oauth-playground` используется бэкендом и не используется для получения токенов, то параметры `Standard flow`
и `Direct access grants` можно отключить:

![521_audience_2.png](img/520_audience_2.png)

![523_audience_3.png](img/520_audience_3.png)

В области видимости `oauth-playground-dedicate` следует создать новый `mapper`:

![524_audience_4.png](img/520_audience_4.png)

![525_audience_5.png](img/520_audience_5.png)

Выбрать тип `Audience`:

![526_audience_6.png](img/520_audience_6.png)

И включить `Add to access token`:

![527_audience_7.png](img/520_audience_7.png)

После получения нового токена секретные данные станут доступны:

![528_audience_8.png](img/520_audience_8.png)

---

### 2. Стратегия ограничения доступа `Roles`

Роли позволяют настроить разрешения для приложения посредством указания, какие роли включаются в токен доступа для приложения.

В поле `aud` токена доступа присутствует значение `account`:

![531_roles_1.png](img/530_roles_1.png)

Это происходит потому, что по-умолчанию у клиента в область видимости попадают все роли, а у пользователя по-умолчанию есть несколько
клиентских ролей для учетной записи клиента, которые предоставляют пользователю доступ к консоли учетной записи Keycloak.

Посредством `role mapping` можно настроить разрешения, предоставляемые пользователю ролью.

Клиент не имеет ролей, назначенных напрямую (?), но имеет область видимости для набора ролей, контролируя какие роли могут быть включены в
токены, отправляемые клиенту.

Т.о. роли, включаемые в токены, представляют собой пересечение ролей пользователя и ролей, которые разрешено использовать клиенту:

![532_roles_2.png](img/530_roles_2.png)

Для удобства пользования по-умолчанию все роли пользователя включаются в токен (это сделано, чтобы не пришлось каждый раз вручную включать
все роли). Выключим эту настройку (`Full scope allowed`):

![541_roles_0.png](img/540_roles_1.png)

![542_roles_1.png](img/540_roles_2.png)

После этого в токене доступа уже нет никаких ролей, а требование `aud` ("audience") теперь включает только
клиент `oauth-backend` (`account`, `realm_access` и `resource_access` уже не отображаются):

<table>
<tr align="center">
<td> <b>Full scope allowed == true</b> </td> <td> <b>Full scope allowed == false</b> </td>
</tr>
<tr valign="top">
<td>

```json
{
  "exp": 1727023439,
  "iat": 1727023139,
  "auth_time": 1727020324,
  "jti": "78176305-4b33-4458-bae7-e92aa4c658f6",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": [
    "oauth-backend",
    "account"
  ],
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "Bearer",
  "azp": "oauth-playground",
  "session_state": "d78f15ca-88e9-4281-9c28-2ce6e5fec789",
  "acr": "0",
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
  "scope": "albums profile email",
  "sid": "d78f15ca-88e9-4281-9c28-2ce6e5fec789",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

</td>
<td>

```json
{
  "exp": 1727029665,
  "iat": 1727029365,
  "auth_time": 1727029365,
  "jti": "af1220b5-2825-47b4-a8e9-c8fbbf057d78",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oauth-backend",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "Bearer",
  "azp": "oauth-playground",
  "session_state": "4ffc23f9-4810-4498-819f-253e6c68acd5",
  "acr": "1",
  "allowed-origins": [
    "http://localhost:8000"
  ],
  "scope": "albums profile email",
  "sid": "4ffc23f9-4810-4498-819f-253e6c68acd5",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

</td>
</tr>
</table>

При попытке получить секретные данные получим отказ:

![543_roles_2.png](img/540_roles_3.png)

Это происходит потому, что сервис разрешает только запросы, включающие роль `myrole`.

#### [Вариант 1: Назначение роли клиенту напрямую](#variant-1)

Клиент может иметь доступ к одной или более клиентских областей видимости.

Это настраивается через закладку `Client scopes` клиента.

Добавим клиенту `oauth-client` в область видимости `oauth-playground-dedicated` роль `myrole`:

![550_roles_for_client_1.png](img/550_roles_for_client_1.png)

![551_roles_for_client_2.png](img/550_roles_for_client_2.png)

![552_roles_for_client_3.png](img/550_roles_for_client_3.png)

![553_roles_for_client_4.png](img/550_roles_for_client_4.png)

Теперь токен доступа содержит роль `myrole` в `realm_access`:

<table>
<tr align="center">
<td> <b>Без роли `myrole`</b> </td> <td> <b>С ролью `myrole`</b> </td>
</tr>
<tr valign="top">
<td>

```json
{
  "exp": 1727029665,
  "iat": 1727029365,
  "auth_time": 1727029365,
  "jti": "af1220b5-2825-47b4-a8e9-c8fbbf057d78",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oauth-backend",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "Bearer",
  "azp": "oauth-playground",
  "session_state": "4ffc23f9-4810-4498-819f-253e6c68acd5",
  "acr": "1",
  "allowed-origins": [
    "http://localhost:8000"
  ],
  "scope": "albums profile email",
  "sid": "4ffc23f9-4810-4498-819f-253e6c68acd5",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

</td>
<td>

```json
{
  "exp": 1727031462,
  "iat": 1727031162,
  "auth_time": 1727029365,
  "jti": "aca9af6a-184f-4242-97cb-def4fdceada9",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oauth-backend",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "Bearer",
  "azp": "oauth-playground",
  "session_state": "4ffc23f9-4810-4498-819f-253e6c68acd5",
  "acr": "0",
  "allowed-origins": [
    "http://localhost:8000"
  ],
  "realm_access": {
    "roles": [
      "myrole"
    ]
  },
  "scope": "albums profile email",
  "sid": "4ffc23f9-4810-4498-819f-253e6c68acd5",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

</td>
</tr>
</table>

И такой токен позволит получить секретные данные:

![554_roles_for_client_5.png](img/550_roles_for_client_5.png)

#### [Вариант 2: Назначение роли клиенту через его область видимости](#variant-2)

Область видимости клиента может иметь область видимости для ролей.

> Для продолжения следует удалить роль `myrole`, назначенную клиенту `oauth-playground` при реализации [**Варианта 1
**](#вариант-1-назначение-роли-клиенту-напрямую).

Создать новую клиентскую область видимости:

![560_roles_for_client_scope_1.png](img/560_roles_for_client_scope_1.png)

Достаточно задать имя области видимости - `myrole`:

![561_roles_for_client_scope_2.png](img/560_roles_for_client_scope_2.png)

На закладке `Scope` назначить область видимости на роль `myrole`:

![562_roles_for_client_scope_3.png](img/560_roles_for_client_scope_3.png)

![563_roles_for_client_scope_4.png](img/560_roles_for_client_scope_4.png)

Теперь клиентской области видимости назначена область видимости на роль `myrole`:

![564_roles_for_client_scope_5.png](img/560_roles_for_client_scope_5.png)

Теперь можно добавить эту клиентскую область видимости клиенту в качестве опциональной (т.е. запрашиваемой явно).

Для этого на закладке `Client scopes` клиента `oauth-playground` нажатием кнопки `Add client scope` выбираем роль `myrole` и нажатием кнопки
`Add` и `Optional` добавляем её в клиентскую область видимости:

![565_roles_for_client_scope_6.png](img/560_roles_for_client_scope_6.png)

![566_roles_for_client_scope_7.png](img/560_roles_for_client_scope_7.png)

![567_roles_for_client_scope_8.png](img/560_roles_for_client_scope_8.png)

Т.к. роль `myrole` является опциональной и будет добавлена в токен только если клиент явно запросит область видимости `myrole`,
то клиенту следует задать параметр scope=`myrole`:

![568_roles_for_client_scope_9.png](img/560_roles_for_client_scope_9.png)

Теперь получаемый токен доступа будет содержать роль `myrole` в секции `reaml_access`:

<table>
<tr align="center">
<td> <b>Без области видимости `myrole`</b> </td> <td> <b>С областью видимости `myrole` (scope == `myrole`)</b> </td>
</tr>
<tr valign="top">
<td>

```json
{
  "exp": 1727042228,
  "iat": 1727041928,
  "auth_time": 1727041927,
  "jti": "dd3be377-2481-44c8-9f10-00b4b7ea2f61",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oauth-backend",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "Bearer",
  "azp": "oauth-playground",
  "session_state": "af02b40a-8bbf-480b-8850-e697d115f2a8",
  "acr": "0",
  "allowed-origins": [
    "http://localhost:8000"
  ],
  "scope": "albums profile email",
  "sid": "af02b40a-8bbf-480b-8850-e697d115f2a8",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

</td>
<td>

```json
{
  "exp": 1727042904,
  "iat": 1727042604,
  "auth_time": 1727041927,
  "jti": "d2056961-c5e5-4b94-b7ea-2b713c3c6b81",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oauth-backend",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "Bearer",
  "azp": "oauth-playground",
  "session_state": "af02b40a-8bbf-480b-8850-e697d115f2a8",
  "acr": "0",
  "allowed-origins": [
    "http://localhost:8000"
  ],
  "realm_access": {
    "roles": [
      "myrole"
    ]
  },
  "scope": "myrole profile email",
  "sid": "af02b40a-8bbf-480b-8850-e697d115f2a8",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

</td>
</tr>
</table>

Это, в свою очередь, позволит получить доступ к секретным данным:

![568_roles_for_client_scope_9.png](img/560_roles_for_client_scope_10.png)


---

### 3. Стратегия ограничения доступа `Scope`

Для ограничения доступа, выдаваемого токеном, можно использовать области видимости.

Прямое применение областей видимости является дефолтным механизмом OAuth2.0 для ограничения разрешений токена доступа.
Использование областей видимости особенно полезно при работе со сторонними приложениями, когда пользователь должен дать согласие
на выдачу приложению доступа к ресурсам от имени самого пользователя.

В Keycloak область видимости OAuth2.0 соответствует клиентской области видимости.

Создадим три области видимости - `albums:view`, `albums:create` и `albums:delete`:

| `albums:view`                             | `albums:create`                           | `albums:delete`                           |
|-------------------------------------------|-------------------------------------------|-------------------------------------------|
| ![570_scopes_1.png](img/570_scopes_1.png) | ![571_scopes_2.png](img/570_scopes_2.png) | ![572_scopes_3.png](img/570_scopes_3.png) |

Добавим клиенту `oauth-playground` созданные клиентские области видимости:

![573_scopes_4.png](img/570_scopes_4.png)

![574_scopes_5.png](img/570_scopes_5.png)

Т.к. мы предполагаем, что приложение всегда требует просмотра альбомов, то области `albums:view` мы назначим **дефолтный** тип,
а областям `albums:create` и `albums:delete` - **опциональный**, потому что возможность создания и удаления альбомов у нас считается
необязательной:

![575_scopes_6.png](img/570_scopes_6.png)

Такой подход называется "**инкрементальной авторизацией**", поскольку приложение запрашивает дополнительные разрешения только тогда, когда
пользователь начинает использовать дополнительную функциональность.

Кроме того, следует убедиться, что в настройках пользователя `oauth-playground` в настройках установлен признак `Consent Required`:

![576_scopes_7.png](img/570_scopes_7.png)

Авторизационный запрос следует отправить без указания параметра `scope`:

![577_scopes_8.png](img/570_scopes_8.png)

Keycloak попросит подтвердить выдачу разрешения на предоставление приложению `oauth-playground` разрешения на **просмотр
фотоальбомов**:

![579_scopes_10.png](img/570_scopes_10.png)

После подтверждения будет получен токен доступа, содержащий разрешение `albums:view` в параметре `scope`:

```json
{
  ...
  "scope": "profile email albums:view",
  ...
}
```

Если пользователю требуется разрешение на **создание фотоальбомов**, то приложения должно явно запросить опциональную область
видимости `albums:create`:

![579_scopes_11.png](img/570_scopes_11.png)

Keycloak запросит соответствующее подтверждение у пользователя:

![579_scopes_12.png](img/570_scopes_12.png)

И, в случае одобрения, вернёт токен доступа, содержащий в параметре `scope` не только разрешение `albums:view`, но и `albums:create`:

```json
{
  ...
  "scope": "albums:create profile email albums:view",
  ...
}
```

Аналогично можно запросить разрешение на **удаление фотоальбомов**:

![579_scopes_13.png](img/570_scopes_13.png)

![579_scopes_14.png](img/570_scopes_14.png)

И, в случае одобрения, получить токен доступа, содержащий в параметре `scope` не только разрешение `albums:view`, но и
разрешение `albums:delete`:

```json
{
  ...
  "scope": "profile email albums:view albums:delete",
  ...
}
```

---

## Валидация токенов доступа

Возможна двумя способами:

- вызов `Token Introspection Endpoint` - способ простой, и, кроме того, дающий приложению меньшую связность с Keycloak, как с сервером
  авторизации;
- непосредственная верификация токена.

### Валидация токена доступа с помощью `Token Introspection Endpoint`

Является стандартной для OAuth2.0 точкой доступа, позволяющей запросить у сервера авторизации сведения о
состоянии токена, а также о разрешениях, ассоциированных с токеном. Кроме того, позволяет не хранить всю информацию о токене в самом
токене, а токен представляет собой скорее ссылку на информацию.
Недостатком использования `Token Introspection Endpoint` является то, что вносится дополнительная задержка в процесс обработки запроса,
а также создаётся дополнительная нагрузка на сервер авторизации. Общим подходом является кэширование верифицированного токена с целью
предотвращения повторной валидации. Время между повторными валидациями токена д.б. относительно коротким, в пределах нескольких минут.

Для выполнения запроса к `Token Introspection Endpoint` необходимы учётные данные для нашего `oauth-backend` клиента и сам закодированный
токен доступа.

В настройках клиента `oauth-backend` следует включить `Client authentication` и сохранить изменения:

![580_validation_1.png](img/580_validation_1.png)

Затем в настройках этого же клиента на закладке `Credentials` скопировать значение секрета клиента:

![580_validation_2.png](img/580_validation_2.png)

Значение секрета сохранить в переменной окружения:

```bash
export SECRET=miEtKqXVw09f5m0O8uJKcgR1zpaLP3ey
```

```bash
echo $SECRET
```

Далее следует получить новый токен доступа:

![580_validation_3.png](img/580_validation_3.png)

```json
{
  "exp": 1727094575,
  "iat": 1727094275,
  "auth_time": 1727091827,
  "jti": "968d896f-de1f-411f-b3bd-386ca6c8f093",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oauth-backend",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "Bearer",
  "azp": "oauth-playground",
  "session_state": "a0bbf7ce-e936-4d0b-b86f-6479ff61c3ba",
  "acr": "0",
  "allowed-origins": [
    "http://localhost:8000"
  ],
  "scope": "profile email albums:view",
  "sid": "a0bbf7ce-e936-4d0b-b86f-6479ff61c3ba",
  "email_verified": true,
  "name": "UserFirstName2 UserLastName2",
  "preferred_username": "keycloak",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org"
}
```

В секции `Encoded` отображается закодированный в `base64` токен доступа:

![580_validation_4.png](img/580_validation_4.png)

Аналогично секрету, сохраним значение зашифрованного токена в переменной окружения:

```bash
export TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjcxMDY5NTEsImlhdCI6MTcyNzEwNjY1MSwiYXV0aF90aW1lIjoxNzI3MTA2NjUxLCJqdGkiOiJmNTMxZjJjYy1mNmJjLTQ4Y2ItOTdjMS0yMTc3ZDY2MjNhNGQiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJvYXV0aC1iYWNrZW5kIiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoib2F1dGgtcGxheWdyb3VuZCIsInNlc3Npb25fc3RhdGUiOiI4NzVhOGZiNS1lZjMzLTQ5MmQtYWVmMi0yMjZkMGI0ZmM5MDgiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCJdLCJzY29wZSI6InByb2ZpbGUgZW1haWwgYWxidW1zOnZpZXciLCJzaWQiOiI4NzVhOGZiNS1lZjMzLTQ5MmQtYWVmMi0yMjZkMGI0ZmM5MDgiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlVzZXJGaXJzdE5hbWUyIFVzZXJMYXN0TmFtZTIiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJrZXljbG9hayIsImdpdmVuX25hbWUiOiJVc2VyRmlyc3ROYW1lMiIsImZhbWlseV9uYW1lIjoiVXNlckxhc3ROYW1lMiIsInBpY3R1cmUiOiJodHRwczovLzU5LmltZy5hdml0by5zdC9hdmF0YXIvc29jaWFsLzI1NngyNTYvNDkyNTExMzI1OS5qcGciLCJlbWFpbCI6ImtleWNsb2FrMkBrZXljbG9hay5vcmcifQ.crmU6nDohqoutD9OXcV3O-tpjtvAppioSrM_l-cA5NER3c1fp-5jPsIjpmY9iHzpAsEuGaYsot1xdHCidsum3dtatL37be3p0RZ9avfuIPTcYRmvssyUQSGhShHDsfU-0-Vc7e3g-zQ5ow3OCekOeiWHQDu-o_WqzJPdRH9c7ogykCPinQTZCrjeN52WbUx1-Oo26W5AsESALRAX2RK-eukoEfPQDixKwUccUHObNEh5ywbkKWY0bLJiL56bvdwm-Dkh7BYsBFLoLWPepVMzSH74o58DzAUXLW-qlVwbkvA2TcH0_DxAZCiReqEIw1ZcJytuZllL5sDCN-NvFwC8-Q
```

```bash
echo $TOKEN
```

Вызовем `Token Introspection Endpoint`:

```bash
curl --data "client_id=oauth-backend&client_secret=$SECRET&token=$TOKEN" http://localhost:8080/realms/myrealm/protocol/openid-connect/token/introspect | jq
```

```json
{
  "exp": 1727106951,
  "iat": 1727106651,
  "auth_time": 1727106651,
  "jti": "f531f2cc-f6bc-48cb-97c1-2177d6623a4d",
  "iss": "http://localhost:8080/realms/myrealm",
  "aud": "oauth-backend",
  "sub": "5ab16a86-6977-41f8-a50c-735b89ecd812",
  "typ": "Bearer",
  "azp": "oauth-playground",
  "session_state": "875a8fb5-ef33-492d-aef2-226d0b4fc908",
  "name": "UserFirstName2 UserLastName2",
  "given_name": "UserFirstName2",
  "family_name": "UserLastName2",
  "preferred_username": "keycloak",
  "picture": "https://59.img.avito.st/avatar/social/256x256/4925113259.jpg",
  "email": "keycloak2@keycloak.org",
  "email_verified": true,
  "acr": "1",
  "allowed-origins": [
    "http://localhost:8000"
  ],
  "scope": "profile email albums:view",
  "sid": "875a8fb5-ef33-492d-aef2-226d0b4fc908",
  "client_id": "oauth-playground",
  "username": "keycloak",
  "active": true
}
```

### Прямая валидация токена доступа в приложении

Состоит из следующих шагов:

1. Получить публичные ключи из `JWKS (JSON Web Key Set)`-точки доступа, предоставляемой Keycloak;
2. Верифицировать подпись токена доступа;
3. Проверить, что срок действия токена доступа не истек;
4. Верифицировать издателя, `audience` и тип токена;
5. Проверить разрешения, интересующие приложение.

> Лучше реализовывать эти этапы имеющимися библиотеками!

---

---

https://developer.okta.com/docs/concepts/oauth-openid/

---

---

# 6. Работа с разными типами приложений

**Внутреннее приложение (First-party Application)** обладает следующими признаками:

- приложением владеет компания;
- неважно, кто его разрабатывает, где хостится приложение, является оно отдельным или Saas-приложением;
- не нужно спрашивать пользователя, даёт ли он разрешение приложению на доступ к данным, т.к. приложение является доверенным и
  администратор, регистрирующий приложение в Keycloak, может сразу одобрить доступ приложения к данным от имени пользователя (опция `Consent
  required` клиента отключена);
- от пользователя требуется только аутентификация.

**Внешнее приложение (Third-party Application)** обладает следующими признаками:

- приложением владеет и управляет другая компания;
- от пользователя требуется дать приложению разрешение на доступ к данным (опция `Consent required` клиента включена);
- от пользователя требуется аутентификация.

---

## 6.1 Обеспечение безопасности веб-приложений

Рассматривая архитектуру приложения следует ответить на следующие вопросы:

- Server-Side Application или Single-Page Application (SPA)?
- Используется ли REST API?
- Если используется REST API, то является оно частью приложения или внешним?

**Proof Key for Code Exchange (PKCE)** - расширение OAuth2.0, связывающее код авторизации с приложением, отправляющим авторизационный
запрос. Такая связка предотвращает компрометацию кода авторизации в случае его перехвата.

### Чего следует избегать при портировании существующих приложений на использование Keycloak:

- сохранение страницы логина в существующем приложении с целью обмена полученных учётных данных на токены путем использования
  гранта `Resource Owner Password Credential` для получения токена. Это подобно интеграции приложения с `LDAP`-сервером.

  **Следует избегать такого подхода**, т.к.:
    - сбор учётных данных в приложении рискует скомпрометировать доступ ко всем приложениям, которые этим приложением использовались;
    - пользователи склонны использовать одни и те же пароли;
    - нет возможности использовать более сильные виды аутентификации (#, двухфакторную аутентификацию);
    - нет возможности использовать все преимущества Keycloak (#, SSO, Social Login);

- встраивание страницы логина Keycloak в iframe внутри приложения.

  **Следует избегать такого подхода**, т.к.:
    - встроенная в приложение страница логина м.б. подвержена уязвимостям, присутствующим в самом приложении;
    - пользователям сложно понять, откуда пришла страница логина и пользователям будет сложно доверять такой странице и вводить в неё
      учётные данные;
    - посторонние `cookie` часто используются для отслеживания переходов между несколькими сайтами, а браузеры становятся всё более
      агрессивными в блокировке сторонних `cookie`, что может привести к тому, что страница логина Keycloak не будет иметь доступа
      к `cookie`, необходимым для её работы.

Как результат, следует свыкнуться с фактом, что **приложение должно перенаправлять пользователя на доверенного поставщика аутентификации**,
особенно в случае `SSO`-сценариев. Это становится все более и более привычным подходом для пользователей.

Примером являются страницы логина Google и Amazon - они не встроены в само приложение и являются внешними страницами логина:

![GoogleAndAmazon_login_pages.png](img/GoogleAndAmazon_login_pages.png)

---

### Защита серверного веб-приложения

1. В Keycloak следует зарегистрировать конфиденциального клиента, что позволит исключить вероятность утечки авторизационного кода;
2. Следует использовать `PKCE`-расширение (Proof Key for Code Exchange), что обеспечит защиту от других типов атак;
3. Необходимо настроить правильное URI-перенаправление для клиента (`redirect_uri`).

> Если не настроить `redirect_uri`, то создастся т.наз. "открытое перенаправление".
> Открытое перенаправление может использоваться при атаке, заставляющей пользователя поверить, что он нажимает на ссылку на доверенный сайт.
>
> Например, если злоумышленник отправляет URL вида `https://trusted-site.com/?redirect_uri=https://attacker.com` то пользователь может
> не заметить, что в указанном доменном имени доверенного сайта перенаправление ведет на атакующий сайт, и нажать ссылку.
>
> Без настроенного `redirect_uri` Keycloak в итоге перенаправит пользователя на сайт злоумышленника.

### Защита разных типов веб-приложений

<table>
<tr align="center"><td>Серверное веб-приложение</td><td>SPA со специальным REST API</td><td>SPA с промежуточным REST API</td><td>SPA с внешним REST API</td></tr>
<tr align="center"><td>

![600_serverside_webapp_security.png](img/600_serverside_webapp_security.png)</td><td>

![610_SPA_dedicated_RESTAPI.png](img/610_SPA_dedicated_RESTAPI.png)</td><td>

![620_SPA_inter_RESTAPI.png](img/620_SPA_inter_RESTAPI.png)</td><td>

![630_SPA_external_RESTAPI.png](img/630_SPA_external_RESTAPI.png)</td></tr>

<tr valign="top"><td>

#### Приложение использует авторизационный код для получения от Keycloak `ID`-токена и установления `HTTP`-сессии:

1. Веб-сервер перенаправляет браузер на страницу логина Keycloak;
2. Пользователь аутентифицируется в Keycloak;
3. Серверному веб-приложению (на `redirect_uri`?) возвращается авторизационный код;
4. Веб-приложение обменивает авторизационный код на токены, используя учетные данные, зарегистрированного клиента Keycloak;
5. Приложение может непосредственно распарсить и проверить полученный от Keycloak `ID`-токен для получения информации об
   аутентифицированном пользователе и установить аутентифицированное `http`-соединение;
6. Все запросы от браузера теперь содержать в себе `cookie`, идентифицирующие `HTTP`-сессию.

> Серверные приложения могут использовать `SAML 2.0` вместо `OpenID Connect`, но последний рекомендуется по причине простоты работы с ним.
</td><td>

#### Защищается подобно серверному веб-приложению:

1. Пользователь жмет кнопку логина, отправляющую запрос на веб-сервер;
2. Веб-сервер перенаправляет браузер пользователя на страницу логина Keycloak;
3. Пользователь аутентифицируется в Keycloak;
4. Авторизационный код возвращается веб-серверу;
5. Веб-сервер обменивает авторизационный код на токены;
6. Приложение получает `ID`-токен напрямую от Keycloak, парсит и верифицирует его, получает из него информацию об аутентифицированном
   пользователе и устанавливает аутентифицированную `HTTP`-сессию;

</td><td>

#### Даёт возможность использовать конфиденциального клиента, а токены недоступны напрямую в браузере, снижая риск утечки токенов (особенно токена обновления):

1. Пользователь жмет кнопку логина, отправляющую запрос на веб-сервер;
2. Веб-сервер перенаправляет браузер пользователя на страницу логина Keycloak;
3. Пользователь аутентифицируется в Keycloak;
4. Авторизационный код возвращается веб-серверу;
5. Веб-сервер обменивает авторизационный код на токены;
6. Приложение получает `ID`-токен напрямую от Keycloak, парсит и верифицирует его, получает из него информацию об аутентифицированном
   пользователе и устанавливает аутентифицированную `HTTP`-сессию. И `Refresh-` и `Access-`токены хранятся внутри HTTP-сессии;
7. Запросы от SPA к REST API содержат `cookie` `HTTP`-сессии;
8. Веб-сервер получает токен доступа от HTTP-сессии и включает его в запросы к внешнему RESP API;
9. Веб-сервер возвращает ответ SPA, включая в него `cookie` `HTTP`-сессии;

> Промежуточный API размещен в том же домене, что и SPA. Такой тип SPA является реализацией шаблона `BFF`, повышающего безопасность,
> делающего SPA проще и портативней, т.к. приложение взаимодействует не напрямую с внешними API, а с REST API, специально созданным для
> обслуживания фронтендового SPA.
>
> Кроме того, браузеры не позволяют SPA вызывать REST API в другом домене без CORS. А поскольку SPA отправляет запросы через
> промежуточный REST API в этом же домене, то не нужно заботиться о CORS.

</td><td>

#### Код авторизации пересылается непосредственно из SPA с применением публичного клиента, зарегистрированного в Keycloak:

1. SPA перенаправляет пользователя на страницу логина Keycloak;
2. После того как пользователь аутентифицирован, авторизационный код возвращается в SPA;
3. SPA обменивает авторизационный код на токены.

> Т.к. SPA работает в браузере, то нет возможности обеспечить безопасность учётных записей клиента и поэтому используется публичный клиент,
> зарегистрированный в Keycloak;

4. SPA имеет непосредственный доступ к `Access Token` и включает его в запрос к REST API;
5. REST API добавляет CORS-заголовки в ответ (иначе браузер не даст SPA прочитать ответ).

> Из-за того, что токены доступны непосредственно в браузере, повышается риск их утечки. Это м.б. компенсировано следующим:
>
> - короткий срок жизни `Refresh Token` (минуты), но длинное время жизни сеанса единого входа (дни);
> - ротация `Refresh Token`, когда попытка его повторного применения приводит к инвалидации сеанса;
> - использование `PKCE` для общедоступного клиента;
> - хранение токенов в `window state` или в сеансе хранения `HTML5` (избегая при этом использования легкоугадываемых ключей,
    вроде `window.sessionStorage.accessToken`);
> - следовать рекомендациям проекта Open Web Application Security Project (OWASP) для защиты от XSS и других видов атак;
> - не использовать сторонние скрипты в приложении.

</td></tr>
</table>

---

### Защита нативных (небраузерных) и мобильных приложений

Следует избегать искушения реализовать страницу логина в самом приложении с целью использовать
грант `OAuth 2.0 Resource Owner Password Credential` для последующего получения токенов т.к.:

- приложение не должно иметь прямого доступа к учётным данным пользователя;
- не получится использовать многие возможности, предоставляемые Keycloak.

Использование авторизационного кода и `PKCE` является более безопасным и, кроме того, позволяет задействовать все возможности Keycloak.

Такой подход подразумевает использование браузера для аутентификации в Keycloak и здесь доступны три решения:

1. Встроенный `web view`. Нежелательный способ, т.к. обладает уязвимостями, которые м.б. использованы для перехвата учётных данных, а также
   не позволяет реализовать SSO (т.к. нет разделяемых между разными приложениями `cookie`);
2. Внешний агент пользователя (дефолтный браузер);
3. Встроенная в приложение браузерная вкладка (доступна на некоторых платформах, таких как Android или iOS). Однако вредоносный код может в
   приложении сымитировать страницу входа, выглядящую как вкладка браузера, и перехватить учётные данные.

![640_native_app_security.png](img/640_native_app_security.png)

1. Приложение открывается страницу логина внешнего браузера (или встроенной браузерной закладки);
2. Пользователь аутентифицируется в Keycloak;
3. Авторизационный код возвращается приложению;
4. Приложение обменивает авторизационный код на токены.

Четыре схемы возврата авторизационного кода в приложение (`OAuth2.0`):

- **Заявленная HTTP-схема (Claimed HTTP-scheme)** - некоторые платформы позволяют приложению заявить HTTP-схему (путь, начинающийся
  с `https://`), который откроет
  URI
  в приложении вместо того, чтобы открыть его в системном браузере;
- **Пользовательская URI-схема (Custom URI-scheme)** - регистрируется в приложении и когда Keycloak перенаправляет на эту схему, то запрос
  отправляется в
  приложение. Такая схема должна соответствовать обратному порядку домена, которым владеет разработчик приложения (например, схема
  `org.acme.app://oauth2/provider-name` соответствует доменному имени `app.acme.org`);
- **Петлевой интерфейс (Loopback Interface)** - приложение м. запустить временный веб-сервер на случайном порту петлевого интерфейса,
  а затем в качестве `redirect_URI` зарегистрировать `http://127.0.0.1/oauth2/providev-name`, чтобы перенаправить запрос на этот временный
  веб-сервер.

> _**Петлевой интерфейс**_ - это виртуальный интерфейс, который всегда доступен, пока работает хотя бы один из IP-интерфейсов сетевого
> устройства и используется устройством для ссылки на самого себя (для связи с другими устройствами не используется).
>
> Задействует адрес `127.0.0.1`, известный также как `localhost`.
>
> Полезен для отладки, поскольку его IP-адрес всегда может быть проверен при включении любого другого интерфейса коммутатора.

- **Специальный `'redirect_URI'`** - специальный адрес `urn:ietf:wg:oauth:2.0:oob` указывает Keycloak отобразить авторизационный
  код, позволяя тем самым пользователю вручную его скопировать и вставить в приложение.

#### Пример защиты нативного или мобильного приложения

1. Зарегистрировать в Keycloak нового клиента с параметрами:

- Client ID: cli
- Client authentication: Off
- Standard flow: Enabled
- Valid Redirect URIs: http://127.0.0.1/callback

2. Запустить [приложение](applications/ch6/app.js):

```bash
$ npm install
...
$ node app.js                                                                                                                                                                                                                                                                                                                   Chapter6|✚2 ✭1
Listening on port: 34659
```

3. Аутентифицироваться в Keycloak:

![641_native_app_security.png](img/650_native_app_security_1.png)

4. После аутентификации страница больше не нужна и её можно закрыть:

![650_native_app_security_2.png](img/650_native_app_security_2.png)

5. Приложение получит авторизационный код и токен доступа:

```bash 
$ node app.js                                                                                                                                                                                                                                                                                                                   Chapter6|✚2 ✭1
Listening on port: 34659

Authorization Code: 27654663-d292-4da7-b6e8-13c524299836.f59ba1c2-73b8-4e41-8f68-8d86bcfe090b.f560c5da-f656-453c-bfa3-a223febffa77

Access Token: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjczNzcxMDgsImlhdCI6MTcyNzM3NjgwOCwiYXV0aF90aW1lIjoxNzI3Mzc2ODA4LCJqdGkiOiIyZGRiNDEwYi0wYTA3LTQ0MDUtODkyOS0xNjMwYzU4MzZiZDciLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiY2xpIiwic2Vzc2lvbl9zdGF0ZSI6ImY1OWJhMWMyLTczYjgtNGU0MS04ZjY4LThkODZiY2ZlMDkwYiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovLzEyNy4wLjAuMSJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1teXJlYWxtIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiIsIm15cm9sZSJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6ImY1OWJhMWMyLTczYjgtNGU0MS04ZjY4LThkODZiY2ZlMDkwYiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiVXNlckZpcnN0TmFtZTIgVXNlckxhc3ROYW1lMiIsInByZWZlcnJlZF91c2VybmFtZSI6ImtleWNsb2FrIiwiZ2l2ZW5fbmFtZSI6IlVzZXJGaXJzdE5hbWUyIiwiZmFtaWx5X25hbWUiOiJVc2VyTGFzdE5hbWUyIiwicGljdHVyZSI6Imh0dHBzOi8vNTkuaW1nLmF2aXRvLnN0L2F2YXRhci9zb2NpYWwvMjU2eDI1Ni80OTI1MTEzMjU5LmpwZyIsImVtYWlsIjoia2V5Y2xvYWsyQGtleWNsb2FrLm9yZyJ9.Ta4GR8QFtvN3bcfg2YrpxMc_bdQrNRTgODeVAc0QQmfW3MRa3X16yItVvDl5nssRKh0L1C8G13jBFblVdw-OC5K5Oq3sRowKisKNig9UKYWhGlgSkCxzZQPYCyyEZ7NcU9BIFewp9_Yeu-5ATP4CbYYhBbSQ34_HEP8ApKDr-FpPq-dlfN3aXdbdzPe3HrFPkJDw6U_HbbQ9pqjp-cmDffUiA5nTVTUMZBkIuSO2tVfir18hraXsxGIzPVUMhy8JM4h4fFUrVC4Um0LWGrhvZ13zIehl0JvDD-m_g4l3NiqHe2c8VR9cZG0eVcExaWUSP7i5MpsRLOB6ZDc7DT5nKg
```

---

### Защита на устройствах с ограниченной возможностью ввода данных (#, SmartTV, приставки и пр.)

Тип предоставления кода устройства работает с помощью приложения, показывающего короткий код, который
пользователь вводит в специальную конечную точку на сервере авторизации на другом устройстве с помощью браузера. После ввода кода
пользователю будет предложено войти в систему, если он еще не вошел в систему. После завершения приложение сможет получить код авторизации с
сервера авторизации.

#### Пример защиты на устройствах с ограниченной возможностью ввода данных

1. Зарегистрировать в Keycloak нового клиента с параметрами:

- Client ID: tv
- Client authentication: Off
- OAuth 2.0 Device Authorization Grant: Enabled

2. Инициализировать процесс авторизации устройства (`Device Authorization Request`) и получить ответ:

```bash
curl --data "client_id=tv" http://localhost:8080/realms/myrealm/protocol/openid-connect/auth/device | jq
```

Ответ:

```bash
$ curl --data "client_id=tv" http://localhost:8080/realms/myrealm/protocol/openid-connect/auth/device | jq                                                                                                                                                                                                                      Chapter6|✚2 ✭6
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   286  100   274  100    12  87344   3825 --:--:-- --:--:-- --:--:-- 95333
{
  "device_code": "tmklWKCxCGEEFd6ZNMfCsjmUPAOpC7UMuR-a41U2cA8",
  "user_code": "JFWE-UYUA",
  "verification_uri": "http://localhost:8080/realms/myrealm/device",
  "verification_uri_complete": "http://localhost:8080/realms/myrealm/device?user_code=JHCI-MPGJ",
  "expires_in": 600,
  "interval": 5
}
```

3. Открыть в любом браузере любого устройства URI, указанный в `verification_uri` и ввести код, полученный в `user_code`:

![660_smartTV_security_1.png](img/660_smartTV_security_1.png)

4. Одобрить предоставление приложению необходимых разрешений:

![660_smartTV_security_2.png](img/660_smartTV_security_2.png)

5. Keycloak подтвердит успешность регистрации:

![660_smartTV_security_3.png](img/660_smartTV_security_3.png)

Окно браузера можно закрыть.

6. Установить полученный `device_code` в переменную окружения:

```bash
export DEVICE_CODE="tmklWKCxCGEEFd6ZNMfCsjmUPAOpC7UMuR-a41U2cA8"
```

```bash
$ echo $DEVICE_CODE
tmklWKCxCGEEFd6ZNMfCsjmUPAOpC7UMuR-a41U2cA8
```

7. Теперь можно отправить запрос на получение токенов `Token Request`:

```bash
curl --data "grant_type=urn:ietf:params:oauth:grant-type:device_code" --data "client_id=tv" --data "device_code=$DEVICE_CODE" -X POST http://localhost:8080/realms/myrealm/protocol/openid-connect/token | jq
```

В ответ будут возвращены `Access Token` и `Refresh Token`:

```bash
$ curl --data "grant_type=urn:ietf:params:oauth:grant-type:device_code" --data "client_id=tv" --data "device_code=$DEVICE_CODE" -X POST http://localhost:8080/realms/myrealm/protocol/openid-connect/token | jq                                                                                                                 Chapter6|✚2 ✭6
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2546  100  2422  100   124   401k  21034 --:--:-- --:--:-- --:--:--  497k
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjczODE2NjMsImlhdCI6MTcyNzM4MTM2MywiYXV0aF90aW1lIjoxNzI3Mzc5ODU3LCJqdGkiOiI0YzkxNjllZi1mODQzLTRhODktODEyZi1lOTFmY2MwMGE5MTgiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidHYiLCJzZXNzaW9uX3N0YXRlIjoiNWMzMjg0MDAtZDc0Mi00ZGU4LWIwOGEtOTY3N2Q2NGFmNGRlIiwiYWNyIjoiMCIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1teXJlYWxtIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiIsIm15cm9sZSJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjVjMzI4NDAwLWQ3NDItNGRlOC1iMDhhLTk2NzdkNjRhZjRkZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiVXNlckZpcnN0TmFtZTIgVXNlckxhc3ROYW1lMiIsInByZWZlcnJlZF91c2VybmFtZSI6ImtleWNsb2FrIiwiZ2l2ZW5fbmFtZSI6IlVzZXJGaXJzdE5hbWUyIiwiZmFtaWx5X25hbWUiOiJVc2VyTGFzdE5hbWUyIiwicGljdHVyZSI6Imh0dHBzOi8vNTkuaW1nLmF2aXRvLnN0L2F2YXRhci9zb2NpYWwvMjU2eDI1Ni80OTI1MTEzMjU5LmpwZyIsImVtYWlsIjoia2V5Y2xvYWsyQGtleWNsb2FrLm9yZyJ9.NFbD9QETKOTtNby9fTJK28F_NOyYcRnpo7oCglvfyaMopMNX2odi0Nt9yVO_HVln7d1YRtfwiMF7gT_aC5u8niAqOKKIv7nFKnD3My0mGGBjEBGdZ_nRMtIFP1QI8Gj2DaXN3GnqWhITNPrUENsVCKgMxBEEDsTDG9vlj4Czad_vxshGKSC6I9MdgIdFdVYKhTv2GiCpI3qaQxlrte-KFolnbA0hIeaU0tUeh8ZH5g2F1hYJkkIG7d1kRxNVW9jSbRyXEyui-mslb5xKJa_OONWOi0hn2pLrlongfPpA5F11FrQ-zEUN_cDfUtggcNZsouJm-6g2eex_xGK6hA3hzw",
  "expires_in": 300,
  "refresh_expires_in": 1735,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxNWM0NGVkZS0zZTYxLTQwMjItODQyNC0wNmM0YTA3MWM4NzcifQ.eyJleHAiOjE3MjczODMwOTgsImlhdCI6MTcyNzM4MTM2MywianRpIjoiYzNkMDc1OGUtZGVmOS00M2FiLTg2ODAtMGNhZmI5NjQ1NmU1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwic3ViIjoiNWFiMTZhODYtNjk3Ny00MWY4LWE1MGMtNzM1Yjg5ZWNkODEyIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6InR2Iiwic2Vzc2lvbl9zdGF0ZSI6IjVjMzI4NDAwLWQ3NDItNGRlOC1iMDhhLTk2NzdkNjRhZjRkZSIsInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjVjMzI4NDAwLWQ3NDItNGRlOC1iMDhhLTk2NzdkNjRhZjRkZSJ9.yVITj8ng6iU-DUcADTMDZ77IrbsajfYUWqy4v_khUqA",
  "token_type": "Bearer",
  "not-before-policy": 0,
  "session_state": "5c328400-d742-4de8-b08a-9677d64af4de",
  "scope": "profile email"
}

```

---

### Защита REST API и сервисов

Когда приложение желает вызвать REST API защищенный Keycloak, то оно сначала получает токен доступа от Keycloak, а затем включает этот
токен в авторизационный заголовок запроса, отправляемого на REST API:

> Authorization: bearer eyJhbGciOiJSUzI1NiIsInR5c…

REST API, получив такой заголовок, верифицирует его и принимает решение о предоставлении доступа.

В микросервисной архитектуре такой подход позволяет расширять аутентификационный контекст, когда один сервис вызывает по цепочке другой:

![670_ms_security.png](img/670_ms_security.png)

Keycloak поддерживает сервисные аккаунты, позволяющие сервису получить токен от собственного имени путем использования типа грантов 'Client
Credential'.

#### Пример защиты REST API

1. Создадим клиента Keycloak со следующими параметрами:

- Client type: OpenID Connect
- Client ID: service
- Client authentication: On
- Standard flow: Unchecked (не будет возможности получить токен используя авторизационный код)
- Implicit Flow Enabled: Unchecked
- Direct Access Grants Enabled: Unchecked
- Service accounts roles: Checked (использовать грант `Client Credential` - позволяет получить токены от собственного имени путем
  использования учетных данных клиента)

![680_rest_api_security.png](img/680_rest_api_security_1.png)

2. Скопируем секрет клиента и разместим его в переменной окружения:

![680_rest_api_security_2.png](img/680_rest_api_security_2.png)

```bash
export SECRET="B9OMqOWwiMk0pqxbg9unlUMsGe4emDa7"
```

```bash
$ echo $SECRET                                                                                                                                                                                                                                                                                                                  Chapter6|✚2 ✭9
B9OMqOWwiMk0pqxbg9unlUMsGe4emDa7
```

3. Обменяем полученный секрет на `Bearer`-токен:

```bash
curl --data "client_id=service&client_secret=$SECRET&grant_type=client_credentials" http://localhost:8080/realms/myrealm/protocol/openid-connect/token | jq
```

Ответ, содержащий `Bearer`-токен:

```bash
$ curl --data "client_id=service&client_secret=$SECRET&grant_type=client_credentials" http://localhost:8080/realms/myrealm/protocol/openid-connect/token | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1487  100  1393  100    94   121k   8413 --:--:-- --:--:-- --:--:--  121k
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHVF9UWDJ6VkowdjNPNmw0aHNDeVhUNzlkX2JQU2taYnJwOFZ2TzJ2MmRZIn0.eyJleHAiOjE3MjczODUzNjEsImlhdCI6MTcyNzM4NTA2MSwianRpIjoiYWE1YTU4MzYtY2VjZC00MmM1LThlYzctODk2OTJiZTdlZTUwIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6Ijg4ZjMxZmI2LTM0ODQtNDA5Ni04NTFjLTI2MzUwZjIwNWZhZCIsInR5cCI6IkJlYXJlciIsImF6cCI6InNlcnZpY2UiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIi8qIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW15cmVhbG0iLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJjbGllbnRIb3N0IjoiMTcyLjI0LjAuMSIsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1zZXJ2aWNlIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yNC4wLjEiLCJjbGllbnRfaWQiOiJzZXJ2aWNlIn0.DGcl1ymD07RqULRHbh6WwyyMzETS6SLzF70kXKFa5n9TroqB-GCplgXJeYM4UDcl2xjbu0OHDDPqyUA_n0srat2BoAcs8yX94uA8LD74MV2frG90EYbgF0pMA6b8XtYVHOT9KlcFwvEBgu_juq1wOCrmBoK2JwfE0T00qUwDf1q-UDBl70tADxmuond7PDIA2mqkqrRg4dLikM6-_wUga2tDoFAGLe-PvaRYv_CjY678jC30EYtDbSYsutf_0gJY6R_vSxATPp3tK7zEWbi03YQOlbYGQZOJRD9Z8gFMtyB-CI1XhAUcPjb3EG4ymsSicgZ4qqVObQm9d0WwZi9h3g",
  "expires_in": 300,
  "refresh_expires_in": 0,
  "token_type": "Bearer",
  "not-before-policy": 0,
  "scope": "profile email"
}
```

4. Сервис REST API получает такой токен в составе запроса и может верифицировать его непосредственно или
   через `Token Introspection Endpoint`.

---

---

# 7. Интеграция приложений с Keycloak

---

### Создадим пользователя Keycloak:

- Username: alice
- Password: alice

---

### Создадим клиентов Keycloak.

#### Для браузерного SPA

Это публичный клиент, работающий в браузере и не имеющий возможности безопасно хранить учётные данные.

- Client ID: mybrowserapp
- Client authentication: OFF
- Standard flow: ON
- Root URL: http://localhost:8080
- Valid Redirect URI: /*
- Web origins: + (разрешаем `Cross-Origin`-запросы от браузерных приложений, работающих в различных доменах, как и Keycloak-сервер)

> Устанавливая `Web origins: +` мы разрешаем отвечать на любые запросы, исходящие от "Valid Redirect URI", указанного в предыдущем пункте.

> **Это минимальная конфигурация для интеграции SPA с Keycloak.**

---

#### Для серверного веб-приложения

Это конфиденциальный клиент, способный безопасно хранить учётные данные на стороне сервера.

- Client ID: mywebapp
- Client authentication: ON
- Standard flow: ON
- Root URL: http://localhost:8080
- Valid Redirect URI: /*

> **Это минимальная конфигурация для интеграции с Keycloak приложений, использующих бекенд (а, возможно, и фронтенд).**
>
> Такие приложения способны самостоятельно поддерживать процесс аутентификации, полагаясь на браузерные механизмы аутентификации запросов
> (например, на `cookie`).

---

#### Для бекенд-приложения, выступающего как сервер ресурсов

Цель такого приложения состоит в авторизации запросов, основываясь на Bearer-токенах для предоставления доступа к защищенным ресурсам.

- Client ID: mybackend
- Client authentication: ON
- Standard flow: ON (?)
- Direct Access Grants: ON (для прямого получения токенов через `Token Endpoint` от имени пользователей)
- Root URL: http://localhost:8080

> Опция `Direct Access Grants` позволяет использовать тип предоставления учетных данных с паролем владельца ресурса OAuth2, что в настоящее
> время считается плохой практикой, и должна быть отключена.


---

#### Для обратного прокси-клиента, работающего перед приложением

Это конфиденциальный клиент, который будет использоваться обратным прокси-сервером для аутентификации и пересылки информации о субъекте его
внутренним службам.

- Client ID: proxy-client
- Client authentication: ON
- Standard flow: ON
- Root URL: http://localhost
- Valid Redirect URI: /*

---

### Выбор архитектуры интеграции

Два подхода:

- встроенный;
- проксированный.

#### Встроенная интеграция

Обычно предоставляется сторонними библиотеками, фреймворками, веб-контейнерами или серверами приложений.
В этом случае приложение непосредственно общается с Keycloak и отвечает за поддержку запросов и ответов `OpenID Connect`.
Таким приложениям обычно требуется реализовать некоторый код или предоставить некоторый вид конфигурации для включения поддержки OIDC.
Любые изменения настроек требуют повторного развертывания приложения:

![700_embedded_integration.png](img/700_embedded_integration.png)

Встроенная интеграция является относительно простой и не требует управления внешними сервисами, что даёт больший контроль над интеграцией.
Если приложение является самодостаточным и применяемая библиотека или фреймворк предоставляют хорошую поддержку `OpenID Connect`, то
интеграция может представлять собой написание нескольких строк кода или создание конфигурационного файла.

#### Проксированная интеграция

В прокси-стиле присутствует промежуточный слой между приложением и Keycloak. Интеграция управляется службой, работающей перед
приложением, и отвечает за обработку запросов и ответов `OpenID Connect` от имени приложения:

![701_proxied_integration.png](img/701_proxied_integration.png)

Таким образом, приложение полагается на заголовки HTTP для извлечения токенов или любых других данных, связанных с безопасностью и
с запросом. Код и конфигурация интеграции находятся за пределами границ приложения и управляются через внешнюю службу.

Проксированная интеграция хорошо подходит для случаев:

- отсутствует контроль над кодом приложения (например, для легаси кода);
- приложение спрятано за обратным прокси или API Gateway и есть желание использовать их возможности;
- требуется возможность контролировать и управлять интеграцией с Keycloak из единого места.

> Обе архитектуры интеграции не взаимоисключают друг друга и даже могут существовать одновременно в пределах одной экосистемы.

---

### [Сертифицированные реализации OpenID Connect](https://openid.net/developers/certified-openid-connect-implementations/)

#### Сертифицированные библиотеки для Java:

- Certified Relying Party Libraries:
    - GKIDP Broker 1.0.0
- Certified OpenID Provider Libraries:
    - Connect2id Server 6.1.2a
    - Gluu Server 2.3
    - Gluu Server 3.1.1
    - MITREid Connect
    - OIDC OP Overlay for Shibboleth IdP v3.2.1 version 1.0

#### Сертифицированные реализации Keycloak:

- Certified OpenID Provider Servers and Services:
    - Keycloak 2.3.0
    - Keycloak 18.0.0
- Certified OpenID Providers for Logout Profiles:
    - Keycloak 18.0.0
- Certified Financial-grade API (FAPI) OpenID Providers:
    - Keycloak 15.0.2
- Certified Financial-grade API Client Initiated Backchannel Authentication Profile (FAPI-CIBA) OpenID Providers:
    - Keycloak 15.0.2

---

### Пример защиты веб-приложения

1. В [настройках веб-приложения](applications/ch7/springboot/webapp/src/main/resources/application.yaml) указать секрет клиента (здесь -
   ранее созданного клиента `webapp`):

```yaml
client-secret: jOhqzq7llncZbZRasaUnRMkqwxo5B8ex
```

2. Запустить [веб-приложение](applications/ch7/springboot/webapp):

```bash
(cd applications/ch7/springboot/frontend;./mvnw spring-boot:run) 
```

3. Зайти на страницу приложения по адресу http://localhost:8080, произойдет перенаправление на страницу аутентификации Keycloak, на которой
   следует указать учётные данные пользователя:

![710_webapp_redirected.png](img/710_webapp_redirected.png)

4. Доступ к приложению получен:

![711_webapp_allowed.png](img/711_webapp_allowed.png)

---

### Пример защиты сервера ресурсов

1. Запустить [сервер ресурсов](applications/ch7/springboot/resource-server):

```bash
(cd applications/ch7/springboot/backend;./mvnw spring-boot:run) 
```

2. Получить токен доступа (использовать секрет для ранее созданного клиента `mybackend`):

```bash
export access_token=$(\
curl -X POST http://localhost:8180/realms/myrealm/protocol/openid-connect/token \
-d "client_id=mybackend&client_secret=Sf35iMnERq5brXckt7wC9ADpFhBl9G5b" \
-H "content-type: application/x-www-form-urlencoded" \
-d "username=alice&password=alice&grant_type=password" \
| jq --raw-output ".access_token" \
)
```

```bash
echo $access_token 
```

3. Теперь можно выполнять запросы:

```bash
curl http://localhost:8080/hello -H "Authorization: Bearer ${access_token}"
```

Если не предоставить токен, то будет возвращена ошибка `401 (Unauthorized)`:

```bash
curl -I http://localhost:8080/hello
```

---

### Пример защиты JavaScript-приложения с использованием Keycloak JavaScript адаптера

1. Запустить [JS-приложение](applications/ch7/keycloak-js-adapter):

```bash
(./applications/ch7/keycloak-js-adapter;npm install) 
```

```bash
(./applications/ch7/keycloak-js-adapter;npm start)
```

2. Зайти на страницу приложения по адресу http://localhost:8080, произойдет перенаправление на страницу аутентификации Keycloak, на которой
   следует указать учётные данные пользователя:

![720_jsapp_redirected.png](img/720_jsapp_redirected.png)

3. Доступ к приложению получен:

![721_jsapp_allowed.png](img/721_jsapp_allowed.png)

---

### Пример защиты Frontend Node.js-приложения с помощью Keycloak Node.js адаптера

1. Инсталлировать пакет адаптера:

```bash
$ npm install keycloak-connect 
```

2. В [конфигурационном файле](applications/ch7/nodejs/frontend/keycloak.json) указать секрет клиента (здесь - ранее созданного
   клиента `webapp`):

```json
"credentials": {
"secret": "jOhqzq7llncZbZRasaUnRMkqwxo5B8ex"
}
```

3. Запустить [Node.jS-приложение](applications/ch7/nodejs/frontend):

```bash
(cd ./applications/ch7/nodejs/frontend;npm install)
```

```bash
(cd ./applications/ch7/nodejs/frontend;npm start)
```

4. Зайти на страницу приложения по адресу http://localhost:8080, произойдет перенаправление на страницу аутентификации Keycloak, на которой
   следует указать учётные данные пользователя:

![730_nodejs_app_redirected.png](img/730_nodejs_app_redirected.png)

5. Доступ к приложению получен:

![731_nodejs_app_allowed.png](img/731_nodejs_app_allowed.png)


---

### Пример защиты Node.js-приложения сервера ресурсов с помощью Keycloak Node.js адаптера

1. В [конфигурационном файле](applications/ch7/nodejs/resource-server/keycloak.json) указать, что приложение является `bearer-only`, т.е.
   принимает только `Bearer`-токены:

```json
  "bearer-only": true
```

> Это заставляет адаптер выполнять локальные проверки и интроспекцию токена с целью выяснить, может ли запрос получить доступ к ресурсам
> приложения.

2. Запустить [Node.jS-приложение](applications/ch7/nodejs/resource-server):

```bash
(cd ./applications/ch7/nodejs/resource-server;npm install)
```

```bash
(cd ./applications/ch7/nodejs/resource-server;npm start)
```

3. Получить Access Token, указав секрет клиента (здесь - ранее созданный клиент `mybackend`):

```bash
export access_token=$( \
curl -X POST http://localhost:8180/realms/myrealm/protocol/openid-connect/token \
-d "client_id=mybackend&client_secret=Sf35iMnERq5brXckt7wC9ADpFhBl9G5b" \
-H "content-type: application/x-www-form-urlencoded" \
-d "username=alice&password=alice&grant_type=password" \
| jq --raw-output ".access_token" \
)
```

```bash
echo $access_token
```

4. Теперь можно выполнять запросы:

```bash
curl http://localhost:8080/hello -H "Authorization: Bearer ${access_token}"
```

```bash
$ curl http://localhost:8080/hello -H "Authorization: Bearer ${access_token}"
Access granted to protected resource%
```

Если не предоставить токен, то будет возвращена ошибка `403 (Forbidden)`:

```bash
curl -I http://localhost:8080/hello
```

---

# 8. Стратегии авторизации


---
















