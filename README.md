# Keycloak

**IAM-решение (Identity and Access Management) - централизованный сервис аутентификации и авторизации, система управления сессиями и
токенами.**

---

### How to export a realm

1. Login to the Docker container shell:

```text
$ docker exec -it keycloak bash
```

2. Proceed to the Keycloak directory `/opt/keycloak/bin`;

3. Run export procedure `./kc.sh export --file <FILE_NAME> --realm <REALM_NAME>`:

```text
bash-5.1$ ./kc.sh export --file myrealm-exported.json --realm myrealm
2024-08-23 08:36:06,423 INFO  [org.keycloak.quarkus.runtime.hostname.DefaultHostnameProvider] (main) Hostname settings: Base URL: <unset>, Hostname: <request>, Strict HTTPS: false, Path: <request>, Strict BackChannel: false, Admin URL: <unset>, Admin: <request>, Port: -1, Proxied: false
2024-08-23 08:36:07,353 WARN  [io.quarkus.agroal.runtime.DataSources] (main) Datasource <default> enables XA but transaction recovery is not enabled. Please enable transaction recovery by setting quarkus.transaction-manager.enable-recovery=true, otherwise data may be lost if the application is terminated abruptly
2024-08-23 08:36:07,641 WARN  [org.infinispan.PERSISTENCE] (keycloak-cache-init) ISPN000554: jboss-marshalling is deprecated and planned for removal
2024-08-23 08:36:07,703 INFO  [org.infinispan.CONTAINER] (keycloak-cache-init) ISPN000556: Starting user marshaller 'org.infinispan.jboss.marshalling.core.JBossUserMarshaller'
2024-08-23 08:36:07,967 INFO  [org.keycloak.connections.infinispan.DefaultInfinispanConnectionProviderFactory] (main) Node name: node_822364, Site name: null
2024-08-23 08:36:08,271 INFO  [org.keycloak.broker.provider.AbstractIdentityProviderMapper] (main) Registering class org.keycloak.broker.provider.mappersync.ConfigSyncEventListener
2024-08-23 08:36:08,580 INFO  [org.keycloak.services] (main) KC-SERVICES0034: Export of realm 'myrealm' requested.
2024-08-23 08:36:08,580 INFO  [org.keycloak.exportimport.singlefile.SingleFileExportProvider] (main) Exporting realm 'myrealm' into file /opt/keycloak/bin/myrealm-exported.json
2024-08-23 08:36:08,965 INFO  [org.keycloak.services] (main) KC-SERVICES0035: Export finished successfully
2024-08-23 08:36:09,001 INFO  [io.quarkus] (main) Keycloak 22.0.0 on JVM (powered by Quarkus 3.2.0.Final) started in 3.178s. Listening on: 
2024-08-23 08:36:09,001 INFO  [io.quarkus] (main) Profile import_export activated. 
2024-08-23 08:36:09,001 INFO  [io.quarkus] (main) Installed features: [agroal, cdi, hibernate-orm, jdbc-h2, jdbc-mariadb, jdbc-mssql, jdbc-mysql, jdbc-oracle, jdbc-postgresql, keycloak, logging-gelf, micrometer, narayana-jta, reactive-routes, resteasy, resteasy-jackson, smallrye-context-propagation, smallrye-health, vertx]
2024-08-23 08:36:09,024 INFO  [io.quarkus] (main) Keycloak stopped in 0.021s
```

4. On local machine the exported file can be found in local Docker container file:

```text
$ sudo find / -name "myrealm-exported.json" -type f
/var/snap/docker/common/var-lib-docker/overlay2/.../diff/opt/keycloak/bin/myrealm-exported.json
```

It's a sudo directory so copy the file to the accessible location:

```text
$ sudo cp /var/snap/docker/common/var-lib-docker/overlay2/10208ebe783a5c88abdd50a8b9503c5c9dc812c05016f17758af4edcff6ebcdb/diff/opt/keycloak/bin/myrealm-exported.json /home/oleg/MyProjects/keycloak-iam/keycloak/config
```

And change the access:

```text
$ ls -la
total 76
drwxrwxr-x 2 oleg oleg  4096 авг 23 11:42 .
drwxrwxr-x 3 oleg oleg  4096 авг 23 09:31 ..
-rw-r--r-- 1 root root 66617 авг 23 11:42 myrealm-exported.json

 11:43:05  oleg@oleg-desktop-linux  ...keycloak-iam/keycloak/config  ⬡ v20.16.0 
$ sudo chown oleg:oleg myrealm-exported.json 
[sudo] password for oleg: 

 11:43:21  oleg@oleg-desktop-linux  ...keycloak-iam/keycloak/config  ⬡ v20.16.0 
$ ls -la
total 76
drwxrwxr-x 2 oleg oleg  4096 авг 23 11:42 .
drwxrwxr-x 3 oleg oleg  4096 авг 23 09:31 ..
-rw-r--r-- 1 oleg oleg 66617 авг 23 11:42 myrealm-exported.json

```

File to be imported by Keycloak during startup must be located in Docker container
path: `/opt/keycloak/data/import/myrealm-exported.json`

---

User console:
http://localhost:8080/realms/myrealm/account/#/

---

### Служебные утилиты Keycloak (директория `/opt/keycloak/bin/`)

| Файл     | Назначение                                             |
|----------|--------------------------------------------------------|
| kc.sh    | Запуск Keycloak с параметрами.                         |
| kcadm.sh | Командная строка администратора.                       |
| kcreg.sh | Командная строка для регистрации и настройки клиентов. |

Версии для Linux имеют расширение `.sh`, а для Windows - `.bat`

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

Недостаток такого подхода в том, что с момента выхода пользователя из системы и до логаута всех приложений может пройти несколько минут
(хотя зачастую этого достаточно).

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

Три вопроса для принятия решения о доступе пользователя к ресурсам:

- кто пользователь?
- какие данные с ним связаны?
- какие у него ограничения на доступ к ресурсам?

В качестве поставщика удостоверений Keycloak выпускает токены для приложений.
Токены, выпущенные Keycloak, несут информацию о пользователе и контекст, в котором пользователь был аутентифицирован.
Такой контекст может содержать информацию о клиенте, используемом пользователем или любую другую информацию, собранную в течение процесса
аутентификации.
Опираясь на данные, переносимые токенами, приложения могут выбирать различные механизмы контроля доступа.

**Существует два основных авторизационных паттерна для ограничения доступа к защищенным ресурсам:**

- контроль на уровне приложения:
    - декларативно (использование метаданных и конфигурации);
    - программно;
- делегирование решения о доступе внешней службе (централизованная авторизация).

> Эти два шаблона не являются взаимоисключающими и могут применяться одновременно.

Keycloak позволяет обмениваться любой информацией, которая может понадобиться для ограничений доступа к ресурсам на уровне приложения.
Также можно выбирать различные авторизационные паттерны.

---

## Role-Based Access Control (RBAC)

Защита ресурсов на основе ролей пользователя.

Две категории ролей Keycloak:

- `realm roles` - роли пользователя в пределах организации, безотносительно клиентов, существующих в realm;
- `client roles` - роли конкретного клиента, значение которых зависит от семантики клиента;

**Разрастание роли (role explosion)** - слишком большое количество ролей затрудняет управление доступом.
Следует избегать слишком детальной ролевой авторизации в системе - роли не для этого.

Keycloak позволяет назначать роли группам. Членство пользователя в группе автоматически делегирует ему роли этой группы.
Такой механизм позволяет избежать индивидуального назначения привилегий многим пользователям.

Keycloak предоставляет концепцию **композитных ролей** - особого типа ролей, состоящих из цепочки ролей, где пользователь, получивший
композитную роль, автоматически получает любую роль из этой цепочки (отдельную роль или другую композитную роль).

Несмотря на мощные возможности использования композитных ролей, применять их следует с осторожностью, т.к. могут возникнуть проблемы с
производительностью, особенно в случае цепочки множества композитных ролей, а также проблемы с управляемостью из-за увеличения количества
ролей в системе и детализации связанных с ними разрешений.

При выборе между групповыми и композитными ролями следует отдавать предпочтение групповым ролям.

Выбранная ролевая модель влияет на размер токенов, выпускаемых Keycloak. В идеале токен д. содержать минимальный набор ролей, необходимых
клиенту для авторизации своих пользователей локально или при доступе к другой службе, использующей эти токены.

## Group-Based Access Control (GBAC)

Защита ресурсов на основе группы, которой принадлежит пользователь.

Пользователи объединяются в группы:

- на основе принадлежности к подразделению организации;
- в соответствии с их ролями в организации.

В Keycloak группы м. образовывать иерархию, по которой можно совершать обход.
Когда Keycloak включает информацию о группах в токен, то для иерархических групп она будет иметь формат `РодительскаяГруппа/ДочерняяГруппа`.
Такая информация о группах будет в каждом выпущенном сервером токене, где пользователь является членом группы.

В отличие от ролей, групповая информация не включается в токены автоматически. Для этого следует ассоциировать клиента (или его область
видимости) со специальным `protocol mapper`-ом.

Не существует дефолтного `protocol mapper`, который автоматически бы включал групповую информацию в токены. Такой маппер для клиента нужно
создавать специально. Или можно создать клиентскую область видимости клиента (`Client scope`) и назначить её клиенту.

Откроем ранее созданного клиента `myclient`. На закладке `Client scopes` клиента отображен список всех областей видимости данного клиента:

![800_myclient_scopes.png](img/800_myclient_scopes.png)

Для создания клиенту нового маппера кликнем на ссылке `myclient-dedicated`:

![801_myclient_dedicated_mappers.png](img/801_myclient_dedicated_mappers.png)

Нажмем `Configure a new mapper` и выберем `Group membership`:

![802_myclient_newmapper_groupmembership.png](img/802_myclient_newmapper_groupmembership.png)

Сконфигурируем и сохраним маппер:

![803_myclient_newmapper_groupmembership_done.png](img/803_myclient_newmapper_groupmembership_done.png)

Далее в пункте меню "Groups" создадим группу под именем "Project Management Office":

![804_new_group.png](img/804_new_group.png)

![805_new_group_done.png](img/805_new_group_done.png)

Теперь добавим в созданную группу пользователя `alice`. Для этого перейдем в настройки этого пользователя и на закладке "Groups" нажмем
"Join group", а затем выберем в появившемся списке группу "Project Management Office" для назначения в неё текущего пользователя:

![806_user_alice_newgroup.png](img/806_user_alice_newgroup.png)

Пользователь `alice` теперь входит в группу "Project Management Office":

![807_user_alice_newgroup_done.png](img/807_user_alice_newgroup_done.png)

Для проверки того, как групповая информация будет отображаться в токенах, перейдем в настройки клиента `myclient` и на закладке
"Client scopes" выберем вложенную закладку "Evaluate", после чего в поле "Users" выберем пользователя `alice` и нажмём кнопки
"Generated access token" и "Generated ID token":

![808_clientscopes_evaluate.png](img/808_clientscopes_evaluate.png)

Будут отображены соответствующие токены:

<table>
<tr align="center">
<td> <b>Access Token</b> </td> <td> <b>ID Token</b> </td>
</tr>
<tr valign="top">
<td>

```json
{
  "exp": 1727557482,
  "iat": 1727557182,
  "jti": "72b9721a-1504-4009-94b6-62902ece9b22",
  "iss": "http://localhost:8180/realms/myrealm",
  "aud": "account",
  "sub": "6bb4bc6a-4ec8-4ac1-8dc5-06a6dac0c49f",
  "typ": "Bearer",
  "azp": "myclient",
  "session_state": "b88942b0-053b-489e-9377-39dd2226bb47",
  "acr": "1",
  "allowed-origins": [
    "http://localhost:8000"
  ],
  "realm_access": {
    "roles": [
      "default-roles-myrealm",
      "offline_access",
      "uma_authorization"
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
  "sid": "b88942b0-053b-489e-9377-39dd2226bb47",
  "email_verified": true,
  "groups": [
    "/Project Management Office"
  ],
  "preferred_username": "alice",
  "given_name": "",
  "family_name": "",
  "email": "alice@alice.com"
}
```

</td> <td>

```json
{
  "exp": 1727557482,
  "iat": 1727557182,
  "auth_time": 0,
  "jti": "2cb6c743-a1ef-4e38-8ab2-57fdc1b2fea4",
  "iss": "http://localhost:8180/realms/myrealm",
  "aud": "myclient",
  "sub": "6bb4bc6a-4ec8-4ac1-8dc5-06a6dac0c49f",
  "typ": "ID",
  "azp": "myclient",
  "session_state": "6caeb128-00de-41c4-969b-e5db78ca0d71",
  "acr": "1",
  "sid": "6caeb128-00de-41c4-969b-e5db78ca0d71",
  "email_verified": true,
  "realm_access": {
    "roles": [
      "default-roles-myrealm",
      "offline_access",
      "uma_authorization"
    ]
  },
  "groups": [
    "/Project Management Office"
  ],
  "preferred_username": "alice",
  "given_name": "",
  "family_name": "",
  "email": "alice@alice.com"
}
```

</td>
</tr>
</table>

Как видим, генерируемые токены теперь содержат информацию о группах, в которых состоит пользователь. Т.е. в данном случае
пользователь `alice` является членом единственной группы `Project Management Office`.

---

## OAuth2.0 Scopes

Keycloak является авторизационным сервером OAuth2. В чистом OAuth2 существует два основных типа приложений:

- клиент;
- ресурсный сервер.

`Access Token` выдаётся клиенту, чтобы клиент мог действовать от имени пользователя, при этом полномочия самого токена
ограничены набором областей видимости, на использование которых пользователь выдал согласие.

В свою очередь, потребителем `Access Token`-а является ресурсный сервер, который должен проверить этот токен и принять решение о доступе
клиента к защищенному ресурсу этого сервера, в соответствии областями видимости, разрешение на использование которых выдал пользователь.

Как видим, авторизация, использующая OAuth2 полностью основана на согласии пользователя.

Фундаментальное различие между использованием областей OAuth2 и другими стратегиями авторизации:

- OAuth2 защищает систему от клиентов (проверяется, разрешено ли клиенту выполнять действие или получать доступ от имени пользователя);
- RBAC и д.р. защищают систему от пользователей.

Keycloak обычно используется в корпоративных сценариях, где клиенты находятся в пределах предприятия, а доступ к требуемым ресурсам зависит
не от согласия пользователей, а от разрешений, выданных системным администратором. Клиенты больше заинтересованы в аутентификации
пользователей, где область доступа определяется ролями, группами или даже конкретными атрибутами, связанными с пользователем.

В этом причина того, что по-умолчанию клиенты в Keycloak настроены так, чтобы не запрашивать согласие пользователя.

---

## Attribute-Based Access Control (ABAC)

ABAC предполагает использование атрибутов, представленных токеном, а также информации о контексте аутентификации.

Когда пользователи аутентифицируются через Keycloak, то токены, выпущенные сервером, содержат значимую информацию о контексте
аутентификации - информацию об аутентифицированном пользователе, клиенте, для которого эти токены выпущены, и прочую информацию, полученную
в процессе аутентификации.

В Keycloak сопоставители протоколов (`protocol mappers`) позволяют сопоставлять любую информацию с токенами, чтобы её можно было
использовать для обеспечения доступа на уровне приложения.
Приложение использует утверждения из токена для расчета того, какие роли были предоставлены пользователю, а затем решить, следует ли
предоставить доступ к определенному ресурсу.

ABAC гибок для поддержки нескольких механизмов контроля доступа, но его нелегко реализовать и управлять.


---

## Keycloak как централизованный сервер авторизации

Стратегии авторизации, описанные ранее, полагаются на специфичный набор данных о пользователя, и, в случае изменений требований к
безопасности, приходится менять и код приложения.

Централизованная авторизация позволяет:

- отделить управление доступом к приложению от самого приложения;
- применять несколько механизмов контроля доступа без привязки их к приложению;
- использовать семантику самого приложения для указания защищаемых ресурсов.

Keycloak может действовать как централизованная служба авторизации с помощью **служб авторизации**. Они основаны на наборе политик,
представляющих различные механизмы контроля доступа к защищаемым ресурсам. Службы авторизации позволяют контролировать доступ к определенным
действиям и атрибутам, связанным с защищаемыми ресурсами. Все это управляется через консоль администрирования Keycloak и REST API.

Службы авторизации Keycloak используют ABAC для обеспечения детальной авторизации.

Набор политик, представляющих различные механизмы контроля доступа, предоставляется из коробки, с возможностью объединения этих
политик.

Распространенной проблемой при использовании централизованного сервера авторизации является необходимость дополнительных обходов для
принятия решения о доступе. Используя авторизацию на основе токенов, служба авторизации позволяет преодолеть эту проблему, выдавая токены
со всеми разрешениями, предоставленными сервером, и приложению не нужно будет выполнять дополнительные сетевые вызовы, а достаточно лишь
локально интроспектировать токен. Служба авторизации также поддерживает инкрементную авторизацию, когда токены выдаются с узким набором
разрешений с возможностью получения новых разрешений по мере необходимости.

---

# Конфигурирование Keycloak для промышленной среды

Установка HAProxy:

```bash
$ sudo apt-get install haproxy
```

Точки доступа, предоставляемые Keycloak-ом делятся на 3 группы:

- группа `Frontend URL`;
- группа `Backend URL`;
- группа `Admin URL`.

Базовый URL для каждой из этих групп (`{scheme}`://`{host}`:`{port}`/`{path}`) влияет на следующее:

- как токены будут выпускаться и валидироваться;
- какими будут ссылки на действия, требующие перенаправления пользователя на Keycloak (например, при сбросе пароля через ссылку, высланную
  на почту);
- каким образом приложение будет обнаруживать эти точки доступа путём получения документа "OpenId Connect Discovery" по пути
  `/realms/{realm-name}/.well-known/openid-configuration`.

---

### Группа `Frontend URL`

Группа `Frontend URL` задаёт URL, используемый пользователями и приложениями для доступа к Keycloak через браузерные процедуры, такие как
доступ к странице логина или переход по ссылке для сброса пароля, а также при привязке токена к определенному домену путем установки его
издателя (например, когда `iss` затребует `ID`, `Access Token` и `Refresh Token`). Основная цель состоит в логической группировке всех
экземпляров Keycloak в кластере в один домен безопасности одного издателя путем использования общего для них базового URL с одной и той же
HTTP-схемой, хостом и портом.

Если `Frontend URL` не задан, а клиенты получают доступ к серверу через TLS (`https://mykeycloak`) или простой HTTP (`http://mykeycloak`),
то результирующий Frontend URL не будет являться согласованным из-за использования различающихся HTTP-схем. Такая
рассогласованность может привести к тому, что клиенты будут использовать разных эмитентов токена и обрабатываться так, как если бы
они находились в разных доменах безопасности. Пользователи не смогут завершить такие процедуры, как сброс пароля или доступ к
странице логина.

Установка базового `Frontend URL` позволяет защититься от таких атак, как `Host Injection`, т.к. любой созданный сервером URL является
фиксированным и контролируется. Это особенно важно при использовании реверсивного прокси или балансировщика нагрузки, не
позволяющих переопределять заголовки запросов перед их перенаправлением на бекендовые ноды.

Помимо прочего, без установленного `Frontend URL` куки не будут распознаваться ни на каких нодах кроме той, где они были созданы, что может
повлиять на такой функционал, как `Single-Sign On`, доступность и масштабируемость.

Примерами точек доступа группы `Frontend URL` могут являться следующие:

- авторизационная точка доступа;
- точка доступа логаута и другие, связанные с управлением сессиями;
- точки доступа, инициирующие процессы при переходе пользователя по ссылке, например, сброс пароля;
- точки доступа, предполагающие создание запросов для перенаправления пользователей на другие локации, например, на страницу логина.

При доступе к кластеру должно быть неважно, какая из нод обрабатывает запрос. Базовый URL должен использовать коммуникацию по безопасному
каналу (HTTPS/TLS) и соответствовать публичному URL экспонируемому Keycloak-ом.

**Группа `Frontend URL` устанавливается опциями `hostname` или `hostname-url`.**

Установка только `hostname` является простейшим способом задать базовый `Frontend URL`, т.к. достаточно указать только доменную часть URL,
где экспонирован Keycloak, и позволить ему автоматически разрешить HTTP-схему и номер порта используя дефолтные значения.

Для этого нужно отредактировать файл `$KC_HOME/conf/keycloak.conf` добавив в него опцию:

> hostname=mykeycloak

Keycloak будет использовать `HTTPS`-схему и стандартный порт `8443`, т.е результирующий URL будет `https://mykeycloak:8443`.

> Для большинства случаев опции `hostname` будет достаточно, потому что обычно Keycloak работает за TLS-прокси и экспонируется с
> использованием `HTTPS`-схемы и стандартного порта `443`.

В некоторых случаях может потребоваться указание полного базового `Frontend URL` (например, если Keycloak экспонируется через реверсивный
прокси с использованием другого пути или порта). Для этого используется параметр `hostname-url`:

> hostname-url=https://mykeycloak:1234/mypath

В этом случае путь будет использован, как есть, без применения дефолтных значений и ожидается, что реверсивный прокси будет прослушивать
указанный безопасный порт `1234` и соответственно перенаправлять запросы к бекендовым нодам.

---

### Группа `Backend URL`

Бекендовые точки доступа связаны с прямым взаимодействием между Keycloak и приложениями. Примерами такого взаимодействия являются:

- интроспекция токена;
- получение информации о пользователе;
- получение токена;
- JWKS.

По-умолчанию, базовым `Backend URL` основан на URL входящего запроса. Обычно упомянутые точки доступа используют публичные доменные имена
чтобы приложения могли обращаться к кластеру, находясь за пределами внутренней сети.
Если клиенты обращаются к кластеру через прокси, переопределяющего заголовки HTTP-схемы, хоста и номера порта, то URL бекендовых точек
доступа будет основан на `Frontend URL`, который публично экспонируется кластером. Обычно не требуется конфигурировать бекендовый
`Backend URL` и достаточно дефолтного поведения. Но если требуется, чтобы клиенты могли подключаться к кластеру напрямую через внутреннюю
сеть, используя `Frontend URL` для доступа к бекендовым точкам доступа, то следует установить параметр `hostname-strict-backchannel=true`.

Этот параметр указывает, что `Frontend URL` должен являться так же и базовым URL для бекендовых точек доступа.

---

### Группа `Admin URL`

Обычно административная консоль Keycloak не должна быть публично доступной. Как и с `Frontend URL` можно установить базовый URL для
управляющих ресурсов и таких точек доступа, как консоль администрирования.

Базовый `Admin URL` устанавливается опциями `hostname-admin` или `hostname-admin-url`.

`hostname-admin` позволяет изменить только доменную часть URL (файл `$KC_HOME/conf/keycloak.conf`):

> hostname-admin=admin.mykeycloak

Параметры HTTP-схемы и номер порта получат дефолтные значения, а базовый URL будет `https://admin.mykeycloak:8443`.

`hostname-admin-url` позволяет задать любой URL:

> hostname-admin-url=https://admin.mykeycloak

При установке базового `Admin URL` любой URL, используемый административной консолью будет основан на нём. Ссылки и статические ресурсы,
используемые для отображения консоли, будут доступны только с использованием этого базового URL.

Настройка `Admin URL` оказывается полезной если нужно сделать административную консоль доступной через безопасную сеть, исключая публичный
доступ к ней.

---

### Подключение TLS (Transport Layer Security)

> TLS это сетевой протокол, позволяющий установить зашифрованное соединение между аутентифицированными участниками соединения через
> незащищенную сеть. Использование TLS для защиты HTTP-трафика образует протокол HTTPS.

Keycloak постоянно обменивается секретными данными с агентами пользователя и приложениями.

Лучшим выбором является установка размера ключа не менее 2048 бит.

Keycloak использует современные протоколы безопасности, такие как `TLS v1.2` и `TLS v1.3`.

Параметры, используемые при настройке HTTPS-подключения:

- `https-protocols` - список разрешённых протоколов;
- `https-key-store-file` - путь к `keystore`-файлу;
- `https-key-store-password` - пароль к `keystore`-файлу;
- `https-certificate-file` - сертификат;
- `https-certificate-key-file` - PEM-файл к сертификату.

Подключение HTTPS состоит из 2-х шагов:

1. Создание Java Keystore (JKS), где будут сохраняться приватные ключи сервера и сертификаты;
2. Конфигурирование HTTPS-слушателей для использования ключей из этого JKS.

#### Пример подключения 1:

1. Скопировать [keystore-файл](applications/ch9/conf/mykeycloak.keystore) в каталог $KC_HOME/conf
2. Добавить в [конфигурационный файл](applications/ch9/conf/keycloak.conf) путь к `keystore`-файлу и пароль к нему:

> https-key-store-file=${kc.home.dir}/conf/mykeycloak.keystore
>
> https-key-store-password=password

#### Пример подключения 2:

1. Предоставить сертификат и соответствующий приватный ключ из PEM-файла:

> https-certificate-file=?
>
> https-certificate-key-file=?

Настройка SSL для конкретного реалма устанавливается параметром "Require SSL":

![900_realm_ssl_for_all.png](img/ch9/900_realm_ssl_for_all.png)

Значение "All requests" означает, что для этого реалма любой запрос к Keycloak обязан использовать безопасный протокол.

---

### Настройка базы данных

Keycloak хранит все данные в единственной БД. Даже если запущено несколько экземляров Keycloak, то всё равно используется одна общая для
всех БД.

БД имеет решающее значение для общей производительности, доступности, масштабируемости, надежности и целостности Keycloak.

Keycloak использует кеширование для минимизации обращений к БД.

По-умолчанию Keycloak настроен на использование H2, но для реальных задач следует использовать более надежные СУБД:

- MariaDB;
- MariaDB Galera;
- MySQL;
- Oracle;
- Microsoft SQL;

Для подключения СУБД используются настройки:

- `db` - вендор БД;
- `db-url-host` - URL БД;
- `db-username` - пользователь БД;
- `db-password` - пароль пользователя БД;

| Параметр               | Назначение                                                | Пример                                      |
|------------------------|-----------------------------------------------------------|---------------------------------------------|
| `db`                   | Вендор БД.                                                | postgres                                    |
| `db-username`          | Пользователь БД.                                          | postgres                                    |
| `db-password`          | Пароль пользователя БД.                                   | postgres                                    |
| `db-schema`            | Используемая схема БД.                                    | public                                      |
| `db-url`               | Полная строка подключения к БД (JDBC URL).                | jdbc:postgresql://keycloak-pg:5432/postgres |
| `db-url-database`      | Имя БД дефолтного JDBC URL выбранного вендора.            | postgres                                    |
| `db-url-host`          | Имя хоста дефолтного JDBC URL выбранного вендора.         | keycloak-pg                                 |
| `db-url-port`          | Номер порта хоста дефолтного JDBC URL выбранного вендора. | 5432                                        |
| `db-url-properties`    | Свойства дефолтного JDBC URL выбранного вендора.          |                                             |
| `db-pool-initial-size` | Исходный размер пула соединений.                          |                                             |
| `db-pool-min-size`     | Минимальный размер пула соединений.                       |                                             |
| `db-pool-max-size`     | Максимальный размер пула соединений (по-умолчанию 100)    | 100                                         |

При указании вендора БД номер порта и прочие параметры соединения будут установлены значениями по-умолчанию.

#### Пример настройки подключения Keycloak к БД:

Указать в [конфигурационном файле](applications/ch9/conf/keycloak.conf):

> db=postgres
>
> db-url-host=keycloak-pg
>
> db-url-database=postgres
>
> db-username=postgres
>
> db-password=postgres

Или:

> db=postgres
>
> db-username=postgres
>
> db-password=postgres
>
> db-url=jdbc:postgresql://keycloak-pg:5432/postgres


---

### Настройка кластеризации

Кластеризация позволяет запустить несколько экземпляров Keycloak (возможно, в разных зонах доступности) таким образом, чтобы выход из строя
нод (или зон доступности) не повлиял на доступность самого Keycloak.

С т.з. масштабируемости кластеризация позволяет изменять количество нод в зависимости от загрузки системы, позволяя поддерживать постоянное
время отклика и пропускную способность.

С т.з. отказоустойчивости кластеризация позволяет восстанавливаться после отказов, предотвращая потерю данных (сохраняемых, в основном, в
кэшах), а также влияет на доступность сервиса в целом.

Кэш Keycloak построен на слое распределенного кэша **Inifinispam** - высокопроизводительного хранилища ключ-значение, работающего в RAM.

Для подключения кластеризации и обеспечения высокой доступности следует выполнить следующее:

- запустить сервер, используя распределенный кэш;
- убедиться, что реверсивный прокси сконфигурирован на распределение нагрузки между различными экземплярами и учет привязки сеансов.

Кластеризация используется по-умолчанию, если сервер запускается в промышленном режиме стартовой командой. Дефолтная конфигурация кэша
считывается из файла `$KC_HOME/conf/cache-ispn.xml`, но параметр `cache-config-file` позволяет предоставить и собственный файл.

В целях отказоустойчивости для хранения состояний Keycloak использует специальный кэш.

Важной настройкой является указание количества реплик Keycloak в кластере.

Количество кэшей указывается в файле `$KC_HOME/conf/cache-ispn.xml` и, например, для кэша сессий выглядит следующим образом:

```xml

<cache-container name="keycloak">
    ...
    <distributed-cache name="sessions" owners="2">
        <expiration lifespan="-1"/>
    </distributed-cache>
    ...
</cache-container>
```

Содержимое распределенного кэша автоматически реплицируется на ноды, количество которые указано в аттрибуте `owners`. Чем больше `owners`
тем больше нагрузка на репликацию, то тем выше надежность. Здесь следует найти баланс.

Кэши реалмов и пользователей являют локальными, они не реплицируются и содержатся в памяти каждой ноды в кластере.
Кэш реалмов (`realms`) отвечает за кеширование данных реалма (клиенты, группы, роли, поставщики удостоверений и процедуры аутентификации).
Кэш пользователей (`users`) отвечает за кеширование данных пользователей (учетные данные, аттрибуты, роли, сопоставление групп).
Их определение в конфигурационном файле `$KC_HOME/conf/cache-ispn.xml` выглядит следующим образом:

```xml

<cache-container name="keycloak">
    ...
    <local-cache name="realms" simple-cache="true">
        <encoding>
            <key media-type="application/x-java-object"/>
            <value media-type="application/x-java-object"/>
        </encoding>
        <memory max-count="10000"/>
    </local-cache>
    <local-cache name="users" simple-cache="true">
        <encoding>
            <key media-type="application/x-java-object"/>
            <value media-type="application/x-java-object"/>
        </encoding>
        <memory max-count="10000"/>
    </local-cache>
    ...
</cache-container>
```

Аттрибут `max-count` задает максимальное количество записей в кэше.

#### Пример кластеризации

Запустим [три одинаковых экземпляра](docker-compose.yml) Keycloak:

- "**keycloak**" на порту `8443`;
- "**keycloak2**" на порту `8543`;
- "**keycloak3**" на порту `8643`;

---

### Настройка реверсного прокси

В промышленной среде реверсный прокси является ключевым компонентом обеспечения высокой доступности.
Реверсный прокси предоставляет общую публичную точку доступа для различных экземпляров Keycloak, распределяя нагрузку среди них используя
набор политик. Экземляры Keycloak обычно работают в приватной сети и реверсный прокси является единственным способом обращения к ним.

Keycloak может использоваться с любым вендором ревесных прокси, но наиболее распространенными являются:

- Apache HTTP Server;
- Nginx;
- F5;
- HAProxy.

Базовые требования при настройке реверсного прокси:

- прекращение и повторное шифрование TLS;
- балансировка нагрузки;
- привязка сессий (Session affinity);
- перенаправление заголовков.

При использовании реверсного прокси Keycloak общается не с клиентом напрямую, а с прокси, который должен уметь передавать требуемые
заголовки от клиента к Keycloak. Ключевыми заголовками для Keycloak являются:

- `Forwarded` - стандартный заголовок, содержащие всю информацию о клиенте, сделавшем запрос. Это предпочтительный заголовок для
  использования по сравнению с заголовками `X-Forwarded-*`;
- `X-Forwarded-For` - нестандартный заголовок, содержащий адрес клиента, сделавшего запрос;
- `X-Forwarded-Proto` - нестандартный заголовок, указывающий протокол, используемый клиентом для коммуникации с прокси;
- `X-Forwarded-Host` - нестандартный заголовок, содержащий хост и номер порта, к которым обращен запрос клиента.

Прокси должен не просто пересылать эти заголовки от клиента к Keycloak, а устанавливать их правильно.

---

### Конфигурации [Keycloak](applications/ch9/conf/keycloak.conf) и [HAProxy](applications/ch9/haproxy/haproxy.cfg) для работы с реверсным прокси

> В `/etc/hosts` задать сопоставление `127.0.0.1 mykeycloak admin.mykeycloak mypostgres`.

| [Keycloak](applications/ch9/conf/keycloak.conf)                   | [HAProxy](applications/ch9/haproxy/haproxy.cfg)                                                            | Примечание                                                                                                                                                                                  |
|-------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `hostname=mykeycloak`                                             |                                                                                                            | Установка доменной части базового URL фронтенда с использованием дефолтных параметров протокола и порта (в результате - `https://mykeycloak:8443`).                                         |
| `hostname-url=https://mykeycloak:1234`                            |                                                                                                            | Альтернативный способ установки базового URL для фронтенда, позволяющий указать параметры протокола и порта.                                                                                |
| `hostname-strict-backchannel=true`                                |                                                                                                            | Бекенд должен использовать тот же URL, что и фронтенд.                                                                                                                                      |
| `hostname-admin=admin.mykeycloak`                                 |                                                                                                            | Доменная часть URL доступа к административной консоли.                                                                                                                                      |
| `hostname-admin-url=https://admin.mykeycloak`                     |                                                                                                            | Альтернативный способ установить URL для доступа к административной консоли.                                                                                                                |
| `https-protocols`                                                 |                                                                                                            | Список применяемых TLS-протоколов (по умолчанию - `TLSv1.2` и `TLSv1.3`).                                                                                                                   |
| `https-key-store-file=/opt/keycloak/conf/mykeycloak.keystore`     |                                                                                                            | Путь к `keystore`-файлу.                                                                                                                                                                    |
| `https-key-store-password=password`                               |                                                                                                            | Пароль к `keystore`-файлу.                                                                                                                                                                  |
| `proxy=reencrypt`                                                 |                                                                                                            | Сообщает Keycloak что реверсный прокси использует другой сертификат (коммуникация м/у прокси и нодами Keycloak повторно шифруется с помощью внутреннего сертификата).                       |
|                                                                   | `global`                                                                                                   | **Параметры всего процесса.** Необязательный раздел [конфигурации](applications/ch9/haproxy/haproxy.cfg).                                                                                   |
|                                                                   | `defaults`                                                                                                 | **Дефолтные значения параметров.** Обязательный раздел [конфигурации](applications/ch9/haproxy/haproxy.cfg).                                                                                |
|                                                                   | `backend keycloak`                                                                                         | **Секция описания бекенда под именем `keycloak`.**                                                                                                                                          |
|                                                                   | `option forwardfor`                                                                                        | Разрешает вставку заголовков `X-Forwarded-*` в запросы, направляемые бекенду.                                                                                                               |
|                                                                   | `http-request add-header X-Forwarded-Proto https`                                                          | Клиент использует протокол `https`.                                                                                                                                                         |
|                                                                   | `http-request add-header X-Forwarded-Host mykeycloak`                                                      | Хост, к которому обратился клиент - `mykeycloak`.                                                                                                                                           |
|                                                                   | `http-request add-header X-Forwarded-Port 443`                                                             | Порт, к которому обратился клиент - `443`.                                                                                                                                                  |
| `spi-sticky-session-encoder-infinispan-should-attach-route=false` |                                                                                                            | Для привязки сессий между клиентом и бекендом Keycloak будет полагаться на прокси.                                                                                                          |
|                                                                   | `cookie KC_ROUTE insert indirect nocache`                                                                  | HAProxy будет устанавливать куки `KC_ROUTE`, значение которого указывает на ноду, к которой подключен клиент.                                                                               |
|                                                                   | `balance roundrobin`                                                                                       | Алгоритм балансировки трафика.                                                                                                                                                              |
|                                                                   | `server kc1 keycloak1:8443 check ssl verify required ca-file /etc/haproxy/mykeycloak.crt cookie keycloak1` | Описание бекенд-ноды 1 в формате `<ВнутреннееИмя>` `<Адрес:Порт>` `<Проверять_Доступность>` `<Применять_SSL>` `<ПроверкаСертификата_Требуется>` `<Сертификат_ПутьКФайлу` `<Куки_Значение>`. |
|                                                                   | `server kc2 keycloak2:8443 check ssl verify required ca-file /etc/haproxy/mykeycloak.crt cookie keycloak2` | Описание бекенд-ноды 2.                                                                                                                                                                     |
|                                                                   | `server kc3 keycloak3:8443 check ssl verify required ca-file /etc/haproxy/mykeycloak.crt cookie keycloak3` | Описание бекенд-ноды 3.                                                                                                                                                                     |
|                                                                   | `frontend mykeycloak`                                                                                      | **Секция описания фронтенда под именем `keycloak`.**                                                                                                                                        |
|                                                                   | `bind *:443 ssl crt /etc/haproxy/haproxy.crt.pem`                                                          | Порт, прослушиваемый фронтендом.                                                                                                                                                            |
|                                                                   | `http-request redirect scheme https unless { ssl_fc }`                                                     | Перенаправлять трафик, пришедший по `http`-схеме на `https`-схему.                                                                                                                          |
|                                                                   | `default_backend keycloak`                                                                                 | Используемый по умолчанию бекенд, на поторый пересылать запросы.                                                                                                                            |
|                                                                   | `frontend stats`                                                                                           | **Секция описания фронтенда под именем `stats`.**                                                                                                                                           |
|                                                                   | `bind *:70`                                                                                                | Порт, прослушиваемый фронтендом.                                                                                                                                                            |
|                                                                   | `stats enable`                                                                                             | Включить использование статистики.                                                                                                                                                          |
|                                                                   | `stats uri /`                                                                                              | URL, для доступа к фронтенду.                                                                                                                                                               |
|                                                                   | `stats refresh 1s`                                                                                         | Интервал автоматического обновления страницы.                                                                                                                                               |

---

# 10. Управление пользователями

Security Assertion Markup Language (SAML)
Lightweight Directory Access Protocol (LDAP)

Панель управления аккаунтом: https://mykeycloak/realms/myrealm/account/#/

---

## Концепция LDAP и Active Directory

LDAP является открытым стандартным протоколом, который м.б. использован для чтения из Active Directory.

Microsoft Active Directory это проприетарный сервер каталогов, используемый для организации IT-активов (компьютеры, принтеры и
пользователи).

LDAP-запись является набором информации, состоящим из трех основных компонентов:

- отличительного имени (Distinguished Name, DN);
- набор атрибутов;
- набор объектных классов.

### Directory Information Tree (DIT)

Серверы LDAP-каталогов представляют данные, упорядоченные в виде древоподобных иерархий, в которых каждая запись может иметь ноль или более
подчиненных элементов. Такая структура называется Информационным Деревом Каталога (Directory Information Tree, DIT).

Каждое дерево имеет одну корневую запись, называемую "**контекстом именования**" или "**суффиксом**".

Следует заметить, что несмотря на аналогию с деревом, LDAP DIT обычно довольно плоские, но с большим количеством записей-"листьев"
(записей, не обладающих подчиненными элементами). Т.е. записей, обладающих подчиненными записями в LDAP-дереве обычно относительно немного.

Любой LDAP-сервер обязательно имеет специальную запись, называемую "корневым DSE", у которой DN представляет собой строку нулевой длины,
один из атрибутов которого называется "контекстами именования" и предназначен для представления списка всех DN, выступающих
контекстами именования для DIT, содержащихся на сервере.

Однако является нормальным иметь на серверах DIT-ы, находящиеся за пределами объявленного набора именованных контекстов, если такие записи
предназначены для предоставления информации о сервере (описывают конфигурацию сервера, предоставляют мониторинговую информацию о состоянии
сервера, описывают схему и т.д.), а не для хранения данных, предоставленных пользователям службы каталогов.

Нет какого-либо стандарта, определяющего структуру LDAP-деревьев, и серверы каталогов могут содержать записи любой структуры иерархии, но
обычно запись, служащая контекстом именования для дерева, попадает в одну из трех категорий:

- запись содержит объект класса "домен" и атрибут именования `dc` ("**Domain Component**"). Например, если организация владеет доменом
  `example.com`, то контекст именования будет чем-то вроде `dc=example,dc=com` (при этом необязательно, что существует запись `dc=com`);
- запись содержит объект класса "организация" и атрибут именования `o` ("**Organization**"). Значением атрибута `o` может выступать
  наименование организации (например, `o=Example Corp`), но также распространенной практикой является использование доменного DNS-имени
  организации (например, `o=example.com`);
- запись содержит объект класса "страна" и атрибут именования `c` ("**Country**"). Значением такого атрибута является двухсимвольный код
  страны (по стандарту `ISO 3166`), где расположен сервер. Нередко кроме наименования страны в иерархию включается и другая географическая
  информация (например `o=Example Corp,l=Austin,st=Texas,c=US`), что обычно используется при именовании субъектов сертификатов.

Обычным является использование ветвей контекста именования для разделения различных типов записей по разным родителям. Например, записи
пользователей могут находиться под `ou=People,dc=example,dc=com`, записи групп под `ou=Groups,dc=example,dc=com`, а записи приложений под
`ou=Applications,dc=example,dc=com`.

#### DSE-запись LDAP-сервера

Каждый LDAPv3-сервер должен иметь специальную запись, предоставляющую информацию о возможностях сервера и данных, которые он хранит. Такая
запись называется "**корневая DSE**" (root DSE, root DSA-specific entry) и имеет нулевое DN (т.е. DN с нулевыми RDN и представлением в виде
пустой строки).

Корневая DSE может содержать следующие атрибуты:

- `namingContexts`;
- `subschemaSubentry`;
- `supportedLDAPVersion`;
- `supportedControl`;
- `supportedExtension`;
- `supportedSASLMechanisms`;
- `supportedFeatures`;
- `supportedAuthPasswordSchemes`;
- `altServer`;
- `vendorName`;
- `vendorVersion`;
- `changelog`;
- `firstChangeNumber`;
- `lastChangeNumber`;

Не все серверы поддерживают или отображают все эти атрибуты (например, `changelog`  м.б. подключен, но сам атрибут не отображаться).

Для понимания возможностей сервера LDAP-клиентам настоятельно рекомендуется использовать информацию, предоставляемую корневым DSE, и
формировать свои запросы корректным образом.

### Distinguished Name (DN) и Relative Destinguished Name (RDN)

DN идентифицирует запись и описывает её позицию в Directory Information Tree (DIT).

DN подобен абсолютному пути в ФС за тем исключением, что путь ФС обычно начинается с корня ФС и при чтении слева-направо описывает спуск по
дереву каталогов. DN же при чтении слева-направо поднимается по дереву. Например DN-запись `uid=john.doe,ou=People,dc=example,dc=com`
представляет запись, являющуюся непосредственным дочерним элементом записи `ou=People,dc=example,dc=com`, которая, в свою очередь, является
непосредственным дочерним элементом записи `dc=example,dc=com`.

```bash
`dc=example,dc=com`
  `ou=People,dc=example,dc=com`
    `uid=john.doe,ou=People,dc=example,dc=com`
```

DN формируется из нуля или более компонентов, разделенных запятыми, называемых "относительными DN" (`RDN`). Например, запись
`uid=john.doe,ou=People,dc=example,dc=com` имеет четыре `RDN`:

- `uid=john.doe`
- `ou=People`
- `dc=example`
- `dc=com`

Каждый `RDN` состоит из пары "`имя атрибута`=`значение`".
Каждый `RDN` обязательно содержит хотя бы одну пару значений, но можно добавлять в него дополнительные пары, объединяя их знаком `+` и такой
`RDN` называется многозначным (Multivalued RDN):

"`cn=John Doe`+`mail=jdoe@example.com`"

Многозначные RDN обычно используются в случаях, когда невозможно гарантировать, что однокомпонентный RDN окажется уникальным среди других
записей на этом же уровне иерархии (например, если есть несколько пользователей с именем `John Doe`, но их почтовые адреса различаются).
Значения в многозначных RDN могут следовать в любом порядке.

Следует отметить, что несмотря на то, что каждый компонент `DN` сам по себе является `RDN`, но общим подходом является ссылаться на самый
левый компонент `DN`-записи как на `RDN` этой записи и ссылаться на атрибуты, включенные в этот `RDN`-компонент, как на именованные
атрибуты.
Таким образом в DN `uid=john.doe,ou=People,dc=example,dc=com`, компонент `uid=john.doe` является `RDN` для этой записи.

Легальным случаем является полное отсутствие компонентов в DN и такой DN называется "DN нулевой длины" ("zero-length DN") или "нулевым
DN" ("null ND"). Нулевой DN м.б. использован в качестве ссылки на специальную запись, называемую "корневой DSE" ("root DSN"),
предоставляющей информацию о сервере каталогов (например, свойства, поддерживаемые данным сервером, версию ПО и др.).

Следует заметить, что нет требований, чтобы самый верхний элемент в LDAP-дереве содержал один элемент. Например, нормальным является случай,
когда существует запись `dc=example,dc=com`, но запись `dc=com` отсутствует.

DN записи, находящейся на самом верху LDAP-дерева называется "**контекстом именования**" или "**суффиксом**".

Записи RDN могут иметь любое количество пробелов и могут являться регистронезависимыми. Например, следующие записи являются эквивалентными:

- dc=example,dc=com
- dc=example, dc=com
- dc = example , dc = com
- DC=EXAMPLE,DC=COM
- 0.9.2342.19200300.100.1.25=Example,0.9.2342.19200300.100.1.25=Com

### LDAP-схема

В LDAP схема предоставляет информацию о метаданных и обязательно содержит следующее:

- синтаксисы атрибутов - определяют типы данных, которые м.б. предоставлены сервером каталогов;
- правила сопоставления - виды сравнений, выполняемых для LDAP-данных;
- типы атрибутов - именованные единицы информации, сохраняемые в записях;
- классы объектов - именованные коллекции типов атрибутов, которые м.б. использованы в записях, содержащих класс, а также указание, какие из
  этих типов атрибутов являются обязательными, а какие - опциональными.

LDAP-схема м.накладывать дополнительные ограничения на структуру данных на сервере.

### Атрибуты

Атрибуты содержат данные записи. Каждый атрибут обладает типом, имеет ноль или более параметров, а также набор значений, составляющих сами
данные.

**Тип атрибута** - это элемент LDAP-схемы, указывающий, каким образом атрибут должен обрабатываться LDAP-клиентами и серверами. Каждый тип
атрибута должен иметь идентификатор (Object Identifier, OID) и ноль или более имён, используемых для ссылки на аттрибут. Кроме того, атрибут
должен иметь синтаксис, определяющий тип данных, которые м.храниться в атрибутах этого типа, а также набор правил сопоставления,
определяющих, как д.выполняться сравнения со значениями атрибутов этого типа.
Также тип атрибута может указывать, разрешено ли атрибуту иметь несколько значений в одной записи и предназначен ли атрибут для хранения
пользовательских данных или используется для работы сервера.

### Классы объектов

Классы объектов - это элементы схемы, определяющие коллекции атрибутов, которые отнести к конкретным типам объектов, процессов или других
сущностей. Каждая запись имеет класс структурного объекта, который обозначает, какой тип объекта представлен записью (например, является ли
запись информацией о человеке, о группе, об устройстве, сервисе и т.д.)

Подобно типам атрибутов, классы объектов обязаны иметь идентификатор, но также могут иметь ноль или более имён. Классы объектов также могут
содержать набор обязательных типов атрибутов (любая запись этого класса обязана содержать эти атрибуты) и/или набор необязательных типов
атрибутов (запись этого класса может дополнительно содержать эти атрибуты).

### Идентификаторы объектов (Object Identifiers, OIDs)

[Таблица наиболее распространенных OID](https://ldap.com/ldap-oid-reference-guide/)

| Код             | Расшифровка            | Назначение                                                                            | Пример                                                                                                                                                                                                                                                       |
|-----------------|------------------------|---------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| dc              | domainComponent        | Метка доменного имени.                                                                | Generic: DNS Entry                                                                                                                                                                                                                                           |
| uid             | userId                 | Связанные с объектом имена входа в систему.                                           | Generic: LDAP Alias,<br/>Samba: Machine                                                                                                                                                                                                                      |
| cn              | commonName             | Имена объекта.<br/> Если объект соответствует человеку, то обычно это его полное имя. | Courier Mail: Account,<br/>Courier Mail: Alias,<br/>Generic: Address Book Entry,<br/>Generic: Organisational Role,<br/>Generic: Posix Group,<br/>Generic: User Account,<br/>Kolab: User Entry,<br/>Samba: Group Mapping,<br/>Thunderbird: Address Book Entry |
| ou              | organizationalUnitName | Названия организационной единицы.                                                     | Generic: Organisational Unit                                                                                                                                                                                                                                 |
| sambaDomainName | sambaDomainName        |                                                                                       | Samba: Domain                                                                                                                                                                                                                                                |
|                 |                        |                                                                                       |                                                                                                                                                                                                                                                              |

Идентификатор объекта является строкой, используемой для уникальной идентификации элементов в LDAP-протоколе и других местах в процессе их
обработки. OID состоит из последовательности номеров, разделенных точкой (например, `1.2.840.113556.1.4.473` является идентификатором,
представляющим собой управление запросом сортировки на стороне сервера).

В LDAP идентификаторы используются для идентификации таких сущностей, как элементы схемы (типы атрибутов, классы объектов, синтаксисы,
правила сопоставления и т.д.), элементы управления (Controls), расширенные запросы и ответы.

В случае с элементами схемы вместо OID-ов могут применяться удобные для пользователей имена.

### Поисковые фильтры

Поисковые фильтры используются для определения критериев идентификации записей, содержащих определенный вид информации. Существует большое
количество различных типов поисковых фильтров:

- на присутствие атрибута;
- на приблизительное равенство значения атрибута определенному значению;
- на равенство значения атрибута определенному значение;
- на наличие подстроки в значении атрибута;
- "больше или равно" и "меньше или равно";
- расширяемые фильтры, позволяющие применять пользовательские правила сопоставления;
- AND, OR, NOT-условия.

Логика фильтров м.б. настроена для различных типов данных и применять различные принципы сравнения (например, не учитывать регистры
символов).

### Поиск базовых DN и области видимости

Поисковые запросы указывают базовый DN-элемент, задающий в какой области дерева каталогов осуществлять поиск элементов, а также область
видимости, определяющую какая часть поддерева должна просматриваться:

- `baseObject` (или `base`) - просматривать только элемент, указанный в базовом DN поискового запроса;
- `singleLevel` (или `onelevel`) - просматривать только элементы, непосредственно подчиненные базовому DN поискового запроса (но не сам
  базовый DN);
- `wholeSubtree` (или `sub`) - просматривать базовый DN поискового запроса, а также всю глубину его подчиненных элементов;
- `subordinateSubtree` - просматривать всю глубину элементов, подчиненных базовому DN, но не сам базовый DN.

### Модификации и типы модификаций

LDAP-клиенты м.использовать модифицирующие запросы для внесения изменений в данные, сохраненные в элементе.

Модифицирующий запрос указывает DN обновляемой записи и список применяемых модификаций. Каждая модификация имеет тип, имя атрибута и
опциональный набор значений атрибутов.

Типы модификаций:

- добавление одного или нескольких значений атрибута в запись;
- удаление одного или нескольких значений атрибута из записи;
- замена набора значений другим набором значений атрибута;
- инкрементная модификация - увеличение или уменьшение целочисленного значения атрибута на указанную величину.

### LDAP URL-ы

URL-адрес LDAP инкапсулирует ряд фрагментов информации, которые м.б. использованы для ссылки на сервер каталогов, определенную запись на
сервере каталогов или критерии поиска для определения соответствующих записей на сервере каталогов.

URL-адреса чаще всего используются в ссылках, в т.ч. для установления клиентских соединений.

Примеры валидных LDAP URL:

- `ldap://` - минимальное представление LDAP URL, содержащее только схему;
- `ldap://ds.example.com:389` - LDAP URL содержащий схему, адрес и номер порта;
- `ldap:///` - LDAP URL содержит схему, дефолтные адрес и порт, а также дефолтный DN строки нулевой длины (обозначается третьим слешем);
- `ldap://ds.example.com:389/dc=example,dc=com` - LDAP URL содержит указание на схему, явное указание адреса и номера порта, а также целевую
  DN-запись `dc=example,dc=com`;
- `ldap://ds.example.com:389/dc=example,dc=com?givenName,sn,cn?sub?(uid=john.doe)` - LDAP URL содержит полный набор критериев поиска, а
  также указание на схему, адрес и номер порта, базовый DN (`dc=example,dc=com`), запрашиваемый список атрибутов (`givenName`, `sn` и `cn`),
  область видимости `wholeSubtree` (`sub`) и фильтр (`(uid=john.doe)`).

### Элементы Управления (Controls)

Элемент управления - это часть информации, которая может быть включена в LDAP-запрос/ответ для предоставления дополнительной информации
об этом запросе/ответе. Позволяет изменить способ, как запрос должен интерпретироваться сервером, а ответ - клиентом.

Например, элемент управления запросом сортировки на стороне сервера может быть включен в поисковый запрос, чтобы указать,
что сервер должен сортировать соответствующие записи определенным образом перед отправкой их клиенту.

Элемент управления LDAP имеет три составляющих:

- обязательный идентификатор объекта (OID), уникально идентифицирующий тип этого элемента управления;
- критичность - флаг, указывающий, является ли элемент управления обязательным к применению сервером (и, в случае, если сервер не
  поддерживает такой элемент управления, то запрос д.б.отклонён) или опциональным (им можно пренебречь);
- необязательное значение, предоставляющее дополнительную информацию, используемую при обработке элемента управления (например, желаемый
  порядок сортировки на стороне сервера).

### Рефералы (Referals)

Реферал - это тип ответа LDAP, указывающий, что сервер не смог обработать запрошенную операцию, но предполагающий, что запрос можно успешно
выполнить в другом месте (на другом сервере или в другой области дерева каталогов (DIT)).

Рефералы м.б. возвращены по разным причинам:

- клиент запросил запись, отсутствующую на сервере, но сервер предполагает, где эта запись может находиться;
- клиент запросил запись, присутствующую на сервере, но сервер не может обработать этот запрос (например, запрос на запись был направлен на
  реплику, предназначенную только для чтения, и реплика перенаправляет этот запрос на другую реплику, которая может выполнить запись);
- данные включают в себя т.наз. "умный реферал" ("smart referral"), который заставляет сервер генерировать реферал на основе содержимого
  записи.

Помимо этого существует связанный с рефералами тип ответа на поисковый запрос, используемый для указания того, что часть поиска м.
проводиться на другом сервере. Это полезно, например, когда набор данных слишком велик для размещения на одном сервере и различные части
дерева каталогов размещаются на разных серверах.

### Запись псевдонима

Запись псевдонима — это особый вид записи, который указывает на другую запись в DIT, подобно тому, как символическая ссылка указывает на
другой файл в файловой системе. Такая запись не имеет подчиненных записей.

Запись псевдонима полезна в операциях поиска.

---

## Интеграция Keycloak с LDAP и Active Directory

Если пользователи, импортированные через LDAP, созданы локально в Keycloak, то это даёт возможность использовать все возможности Keycloak по
управлению идентификацией и доступом.
Если пользователи не создаются, то Keycloak выступает в качестве брокера для аутентификации пользователей с использованием LDAP-каталога.

Понятие "федеративности" пользователей обозначает доверительные отношения, установленные между Keycloak и внешним хранилищем идентификации (
в данном случае это LDAP-каталог) таким образом, что обе стороны используют общие данные для управления идентификацией и доступом.

LDAP-мапперы - это специальный функционал, позволяющий сопоставлять информацию между LDAP и Keycloak.

---

## Пример настройки связи между Keycloak и сервером каталогов

### Содержимое базы данных OpenLDAP

Содержимое создано вручную и экспортировано в [ldif-файл](applications/ch10/openldap/backup_no_sys_attrs.ldif) для последующего импорта.

![OpenLDAP_Group.png](img/ch10/OpenLDAP_Group.png)

![OpenLDAP_People.png](img/ch10/OpenLDAP_People.png)

![OpenLDAP_Roles.png](img/ch10/OpenLDAP_Roles.png)

### Настройки User Federation

#### Синхронизация пользователей:

![UserFederation_1.png](img/ch10/UserFederation_1.png)

![UserFederation_2.png](img/ch10/UserFederation_2.png)

![UserFederation_3.png](img/ch10/UserFederation_3.png)

![UserFederation_4.png](img/ch10/UserFederation_4.png)

Список пользователей можно синхронизировать вызовом действия "Sync all users":

![UserFederation_5.png](img/ch10/UserFederation_5.png)

Результирующий список пользователей (поиск по фильтру `*`):

![UserFederation_6.png](img/ch10/UserFederation_6.png)

#### Синхронизация групп:

![Group_LDAP_mapper_1.png](img/ch10/Group_LDAP_mapper_1.png)

![Group_LDAP_mapper_2.png](img/ch10/Group_LDAP_mapper_2.png)

![Group_LDAP_mapper_3.png](img/ch10/Group_LDAP_mapper_3.png)

Результирующий список групп:

![Group_LDAP_mapper_4.png](img/ch10/Group_LDAP_mapper_4.png)

#### Синхронизация ролей:

![Role_LDAP_mapper_1.png](img/ch10/Role_LDAP_mapper_1.png)

![Role_LDAP_mapper_2.png](img/ch10/Role_LDAP_mapper_2.png)

Результирующий список ролей:

![Role_LDAP_mapper_3.png](img/ch10/Role_LDAP_mapper_3.png)

В результате импортированный пользователь будет иметь привязку и к ролям и группам:

|        | Role                                                                   | Group                                                                    |
|--------|------------------------------------------------------------------------|--------------------------------------------------------------------------|
| User01 | ![User1_Imported_LDAP_Role.png](img/ch10/User1_Imported_LDAP_Role.png) | ![User1_Imported_LDAP_Group.png](img/ch10/User1_Imported_LDAP_Group.png) |
| User02 | ![User2_Imported_LDAP_Role.png](img/ch10/User2_Imported_LDAP_Role.png) | ![User2_Imported_LDAP_Group.png](img/ch10/User2_Imported_LDAP_Group.png) |

> ВОЗМОЖНАЯ ОШИБКА!
> Скорее всего настройка ролей в Active Directory выполнена неправильно, что при попытке отображения списка пользователей у роли ("Realm
> roles" => "Role.." => "Users is role") вызывает ошибку:
>
> ![RealmRoles_LDAP_UsersInRole_Error_1.png](img/ch10/RealmRoles_LDAP_UsersInRole_Error_1.png)
>
> ![RealmRoles_LDAP_UsersInRole_Error_2.png](img/ch10/RealmRoles_LDAP_UsersInRole_Error_2.png)

---

## Keycloak как брокер удостоверений (Identity Broker)

Keycloak выступает в качестве промежуточного сервиса для аутентификации и репликации пользователей от целевого поставщика удостоверений.

Роль брокера удостоверений позволяет решить ряд задач:

- интеграция с социальными сервисами;
- создание точки интеграции для устаревшей системы управления идентификацией;
- обмена данными об идентификации между партнерскими организациями.

Keycloak позволяет использовать два основных типа поставщиков удостоверений (в зависимости от поддерживаемых протоколов безопасности):

- SAML v2;
- OpenID Connect v1.0.

Применяя брокер удостоверений пользователи могут использовать существующий аккаунт для аутентификации - информация о
пользователе будет импортирована из стороннего поставщика идентификации и пользователь станет пользователем реалма и вся функциональность
Keycloak станет доступна, включая ограничения безопасности, налагаемые реалмом.

---

### В отдельном экземпляре Keycloak создать поставщика удостоверений OpenID Connect

1. Создать реалм "third-party-provider":

![OIDC_provider_realm.png](img/ch10/OIDC_provider_realm.png)

2. Создать в реалме "third-party-provider" клиента "broker-app":

![OIDC_provider_client_01.png](img/ch10/OIDC_provider_client_01.png)

![OIDC_provider_client_02.png](img/ch10/OIDC_provider_client_02.png)

![OIDC_provider_client_03.png](img/ch10/OIDC_provider_client_03.png)

Его секрет - `tPzHIHCWB93OTZS4HecT8vMCuaYPXA0e`:

![OIDC_provider_client_04.png](img/ch10/OIDC_provider_client_04.png)

3. Создать в реалме "third-party-provider" пользователя "third-party-user":

![OIDC_provider_user_01.png](img/ch10/OIDC_provider_user_01.png)

Его пароль - `third`:

![OIDC_provider_user_02.png](img/ch10/OIDC_provider_user_02.png)

---

### Создать нового поставщика идентичности "OpenID Connect v1.0" под именем

1. В экземпляре Keycloak, для которого требуется аутентификация, в реалме "myrealm" выбрать поставщика идентичности "OpenID Connect v1.0":

![OIDC_client_IdentytyProviders.png](img/ch10/OIDC_client_IdentytyProviders.png)

2. Создать нового поставщика идентичности  "OpenID Connect v1.0" под именем "My Third-Party Provider":

![OIDC_client_provider_01.png](img/ch10/OIDC_client_provider_01.png)

> Следует обратить внимание:
> - в нередактируемом поле "Redirect URI" указан адрес, который мы ранее указали в поле "Root URL" при настройке провайдера;
> - в поле "Client ID" и "Client secret" указаны значения, которые ранее были установлены для клиента при настройке провайдера.

Если установлен флаг "Use discovery endpoint" и указан URL `.well-known/openid-configuration` то значения всех URL будут заполнены
автоматически:

![OIDC_client_provider_02.png](img/ch10/OIDC_client_provider_02.png)

---

### Аутентифицировать нового пользователя в реалме "myrealm"

1. Переходим в консоль аккаунтов реалма "myrealm" по адресу https://haproxy/realms/myrealm/account/#/, гда заходим в меню аутентификации
   нажатием кнопки "Sign in"

![OIDC_user_01.png](img/ch10/OIDC_user_01.png)

2. В меню аутентификации нажимаем кнопку с именем созданного нами OIDC-провайдера "My Third-Party Provider":

![OIDC_user_02.png](img/ch10/OIDC_user_02.png)

3. Аутентифицируемся с ранее заданными в поставщике удостоверений OpenID Connect именем пользователя и паролем (`third-party-user`/`third`):

![OIDC_user_03.png](img/ch10/OIDC_user_03.png)

4. После успешной аутентификации откроется меню, предлагающее заполнить дополнительные данные о пользователе (имя и фамилия):

![OIDC_user_04.png](img/ch10/OIDC_user_04.png)

5. После нажатия кнопки "Submit" мы оказываемся в меню аутентифицированного и авторизованного пользователя "third-party-user":

![OIDC_user_05.png](img/ch10/OIDC_user_05.png)

6. Новый пользователь появится и в списке пользователей реалма "myrealm":

![OIDC_user_06.png](img/ch10/OIDC_user_06.png)

---

## Keycloak как система управления сессиями и токенами

Как часть управления аутентификационным процессом Keycloak создает серверные сессии и сопоставляет их с токенами.

Использование сессий позволяет Keycloak поддерживать контекст аутентификации, благодаря чему можно:

- отслеживать активность клиентов и пользователей;
- проверять валидность токенов;
- решать, не пора ли клиентам и пользователям аутентифицироваться повторно (для уменьшения поверхности атаки в случае утечки токенов);
- предоставлять возможности Single Sign-On (`SSO`, например, для единого доступа к разным клиентам одного реалма);
- принудительно прекращать активность пользователей, предотвращая нежелательный доступ.

Сессии кэшируются в памяти и разделяются между разными нодами в кластере. При этом такие показатели, как количество активных сессий, время
их жизни и привязка к нодам (node affinity) являются ключевыми факторами, влияющими на сетевую нагрузку, использование RAM и CPU.

> Существует специфический вид сессий - `Offline Session`, которые хранятся не в памяти, а в базе данных.

> Keycloak инвалидирует сессии с помощью отдельного фонового процесса, запускаемого с определенной периодичностью (по умолчанию - 15 минут).

### Уровни сессий Keycloak:

- **1-й уровень: SSO-сессия** или **пользовательская** сессия. Предназначена для отслеживания активности пользователей безотносительно
  клиента. На этом уровне отслеживается время жизни сессий и их активность (с целью досрочной инвалидации при простое);

> SSO-сессия подобна HTTPS-сессии - обе используются для отслеживания и поддержки состояния между несколькими запросами от одного и того же
> агента.

- **2-й уровень: Клиентская сессия**. Используется для отслеживания активности пользователей с привязкой к клиентам, в которых пользователь
  аутентифицирован. Токены используются на сессиях клиентского уровня.

> Когда инвалидируется **SSO-сессия**, то инвалидируются и все связанные с ней клиентские сессии вместе с их токенами.
>
> Когда инвалидируется **клиентская сессия**, то это принуждает клиентов аутентифицироваться повторно, чтобы обновить свои токены. Повторная
> аутентификация пользователей необязательна, хотя они и могут быть перенаправлены на Keycloak по причине того, что клиенты
> аутентифицировались повторно.

Keycloak позволяет выполнить настройки таймингов для сессий как в целом, так и с привязкой их к клиентам.

#### Видимость сессий Keycloak:

- реалм (администратор видит количество активных сессий для каждого клиента этого реалма);
- клиента (все сессии клиента);
- пользователя (все сессии пользователя).

---

### Куки Keycloak и их связь с сессиями

#### KEYCLOAK_IDENTITY и KEYCLOAK_IDENTITY_LEGACY

Содержит токен с идентификатором аутентифицированного пользователя.

Это куки, устанавливаемый Keycloak после того, как пользователь успешно аутентифицирован, и используемый для сопоставления браузерной сессии
с пользовательской сессией на сервере.

Устанавливается по умолчанию как `HttpOnly` для предотвращения `XSS`-атаки (Cross-Site Scripting) или угона сессии. Срок жизни этого куки
основан на максимальном сроке, заданном для пользовательских сессий.

Если этот куки окажется скомпрометирован (украден), то и сессия пользователя будет скопрометирована.
Лучшей защитой от компрометации является работа с Keycloak исключительно по HTTPS, когда этот куки никогда не передаётся в открытом виде.
Кроме того, установка атрибута `SameSite=None` гарантирует, что этот куки будет передаваться в межсайтовых запросах исключительно по
безопасному соединению.

> Безопасной моделью использования куки является недоступность файлов куки сторонним сервисам, если не указано иное.
>
> Изначально, если файл куки используется в собственном контексте, то следовало устанавливать атрибуты `SameSite=Lax` или `SameSite=Strict`,
> но разработчики часто забывали устанавливать эти значения, что приводило к брешам в безопасности.
>
> Поэтому для явного разрешения стороннего доступа к файлам куки сейчас используется новый параметр `SameSite=None` с дополнительным
> аттрибутом `Secure`, чтобы межсайтовые файлы куки были доступны только по HTTPS.

Действие куки `KEYCLOAK_IDENTITY` автоматически не прекращается при инвалидации пользовательской или клиентской сессии и браузеры могут
по-прежнему присылать этот куки, даже когда он уже не будет связан с активной сессией. Получив недействительный куки, Keycloak аннулирует
его и заставит пользователя повторно пройти аутентификацию.

Куки `KEYCLOAK_IDENTITY_LEGACY` предназначен помочь старым браузерам, не поддерживающим настройку `SameSite=None;Secure`

#### KEYCLOAK_SESSION и KEYCLOAK_SESSION_LEGACY

Куки содержит идентификатор текущей браузерной сессии.

Используется для сохранения сессионной информации (идентификатор и другие данные сессии), позволяя Keycloak идентифицировать
пользовательскую сессию и управлять ей.

Куки `KEYCLOAK_SESSION_LEGACY` используется для поддержки старых приложений.

#### AUTH_SESSION_ID и AUTH_SESSION_ID_LEGACY

Идентификатор текущей аутентификационной сессии.

При каждой аутентификации пользователя создаётся новая аутентификационная сессия и её уникальный идентификатор сохраняется в этом куки,
позволяя Keycloak отслеживать сессию и ассоциировать её с конкретным пользователем.

Куки `AUTH_SESSION_ID_LEGACY` используется для поддержки старых приложений.

---

### Управление токенами

Т.к. токены обычно привязаны к сессиям, то валидность токенов зависит от сессий. Токены обладают собственным временем жизни, которое не
обязательно зависит от времени жизни сессий.

Keycloak использует токены в формате JWT (JSON Web Token), что позволяет приложениям валидировать эти токены локально, не обращаясь
для этого к серверу. Однако, это может привести к ситуации, когда еще живой токен связан с уже исчезнувшей сессией, но приложение его
примет. Поэтому важно выбирать разумную стратегию отзыва токена, а также прибегать к интроспекции токена, используя **Keycloak Introspection
Endpoint** (`/protocol/openid-connect/token/introspect`).

В зависимости от способа получения токена от Keycloak токены делятся на три вида:

- токен идентификатора (`ID Token`) - короткоживующий токен;
- токен доступа (`Access Token`) - короткоживущий токен, часто используемый в запросах для доступа к защищенным ресурсам ("Bearer") и от
  этого легко перехватываемый. Здесь особую важность имеет ограничение времени жизни такого токена;

> `Access Token` в Keycloak имеет такое же время жизни, как и `ID Token` и задаётся одним и тем же параметром "**Access Token Lifespan**" (
> для реалма это в настройках реалма, закладка "Tokens", а для клиента это в настройках клиента, закладка "Advanced").

- токен обновления (`Refresh Token`) - относительно долгоживущий вид токенов, время жизни которого зависит от времени жизни
  пользовательских и клиентских сессий. Являются привлекательной целью для атаки, поэтому время их жизни тоже следует выбирать разумно.

> Время жизни `Refresh Token` рассчитывается на основе времени жизни клиентских сессий, установленного настройкой параметра "**Client
Session Idle**" на уровне реалма или клиента. Если время жизни для клиентской сессии явно не установлено, то Keycloak будет использовать
> значение, установленное для пользовательской сессии параметром "**SSO Session Idle**".
>
> Для клиента можно явно установить время жизни `Refresh Token` параметрами "**Client Session Idle**" и "**Client Session Max**" в
> настройках клиента на закладке "Advanced".

`Refresh Token`:

- всегда связан с клиентской сессией;
- считается действительным, только если связанные с ним сеансы пользователя и клиента не истекли;
- м.б. использован клиентами для получения новых токенов, только если соответствующий сеанс клиента еще активен.

**Ротация `Refresh Token`-ов** - это стратегия при которой токен обновления м.б. использован только определённое числе раз, после чего он
инвалидируется. Это заставляет клиента для получения нового набора токенов повторно аутентифицироваться. Т.о. только законный клиент сможет
получить новый токен обновления. Помогает не только уменьшить поверхность атаки, но и быстро определить момент утечки.

> Настройка подключается для реалма на закладке "Tokens" параметром "**Revoke Refresh Token**". Параметр "**Refresh Token Max Reuse**"
> задаёт число использований `Refresh Token` и по умолчанию равен нулю, что означает **однократное** использование токена обновления.

Для публичных клиентов, поскольку они изначально небезопасны, следует использовать взаимную аутентификацию клиента ("**Mutual TLS Client
Authentication**"), где сертификат клиента используется для привязки токенов к клиенту, для которого они были выпущены, тем самым
предотвращая использование утёкших токенов обновления.

---

# SPI (Service Provider Interface)

Три основных интерфейса Keycloak:

- **SPI** - интерфейс верхнего уровня, предназначенный для загрузки и описания различных функциональных реализаций;
- **ProviderFactory** - интерфейс фабрики сервисов, определяющий контракт для управления жизненным циклом конкретной реализации и создание
  экземпляров Provider;
- **Provider** - интерфейс сервиса, созданного для реализации функциональности.

![KeycloakInteraceImplementations.jpg](img/ch13/KeycloakInteraceImplementations.jpg)

Для создания пользовательского провайдера функциональности этот провайдер д.б.:

1. упакован в JAR;
2. JAR должен содержать дескриптор сервиса, позволяющие Keycloak обнаружить и инициализировать провайдер;
3. JAR д.б. размещен в каталоге `$KC_HOME/providers` сервера Keycloak;
4. для подключения нового провайдера сервис Keycloak следует перезапустить;

Дескриптор сервиса - это файл, расположенный в директории `META-INF/services` JAR-файла, с именем, являющимся полностью квалифицированным
именем реализации ProviderFactory:

> META-INF/services/com.acme.MyProviderFactory

Содержимым файла является указание на класс реализации фабрики:

> com.acme.MyFirstProviderFactory.class

### Публичные и приватные SPI

SPI организованы в два модуля:

- keycloak-server-spi - публичные модули. Подразумевается, что именно они используются сторонними разработчиками. Поэтому их интерфейсы
  лучше документированы и поддерживается максимальная совместимость между релизами;
- keycloak-server-spi-private - приватные модули. Использовать возможно, но они хуже документированы и обратная совместимость не
  гарантируется.

### Жизненный цикл провайдера функциональности

**KeycloakSessionFactory** - реестр всех провайдеров, имеющихся на сервере. Отвечает за управление их жизненным циклом.

Когда Keycloak запускается, то для инициализации и регистрации всех имеющихся ProviderFactory создаётся экземпляр KeycloakSessionFactory.
При корректной остановке Keycloak работающий экземпляр KeycloakSessionFactory предоставляет всем ProviderFactory возможность корректно
освободить используемые ресурсы.

**KeycloakSession** - сессия обработки запроса.

Когда Keycloak обрабатывает запросы, то для каждого из них KeycloakSessionFactory создаёт свой экземпляр KeycloakSession, который
служит точкой входа для управления реалмом, пользователями, клиентами, сессиями, текущим запросом, а также обладает доступом к экземплярам
провайдера. Экземпляры провайдера для сессии создаются только один раз и кешируются на время жизни KeycloakSession.

Жизненный цикл ProviderFactory связан с жизненным циклом сервера и состоит из следующих шагов:

![FactoryInitialization.jpg](img/ch13/FactoryInitialization.jpg)

1. Keycloak загружает все доступные ProviderFactory каждого SPI;
2. Для каждой фабрики вызывается метод `ProviderFactory#init` с передачей в него конфигурации Provider;

> Метод `ProviderFactory#init` вызывается на ранней стадии, когда фабрики все еще находятся в процессе регистрации. И если фабрика не
> зависит от других фабрик или от KeycloakSession, то этого шага должно быть достаточно для инициализации фабрики.

3. После того как все ProviderFactory инициализированы и зарегистрированы, для каждой фабрики вызывается метод `ProviderFactory#postInit` с
   целью выполнить дополнительные шаги по инициализации, с передачей в него ссылки на KeycloakSessionFactory.

> Т.к. метод `ProviderFactory#postInit` вызывается уже после регистрации **всех** фабрик, то это позволяет фабрике выполнять дополнительные
> шаги по инициализации с использованием других поставщиков и самого KeycloakSession.

При деинициализации выполняются аналогичные шаги, но для каждой фабрики вызывается только метод `ProviderFactory#close`.

Жизненный цикл Provider связан с жизненным циклом запроса. ProviderFactory создаёт Provider в качестве реакции на запрос, а уничтожает его
при завершении обработки запроса:

![ProviderCreation.jpg](img/ch13/ProviderCreation.jpg)

### Управление темами оформления

Тема м.б. задана двумя способами:

1. Разворачивание в виде JAR-файла;
2. Копирование темы в директорию `$KC_HOME/themes`;

Независимо от способа установки темы должна использоваться определенная структура директорий - каждая поддиректория в `$KC_HOME/themes` -
это встроенная тема со всеми необходимыми конфигурациями и ресурсами, требуемыми для отрисовки страниц.

> Встроенная дефолтная тема Keycloak находится в файле `$KC_HOME/lib/lib/main/org.keycloak.keycloak-themes-22.0.0.jar`, пример его
> содержимого [здесь](applications/ch13/org.keycloak.keycloak-themes-22.0.0).

Например, в директории [theme](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme) есть три темы:

- [base](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/base) - основа, расширяемая другими темами, в которой
  размещаются шаблоны страниц, пакеты сообщений для интернационализации и общие ресурсы;
- [keycloak](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/keycloak) - дефолтная тема, используемая в случае, если для
  реалма не установлено никаких других тем;
- [keycloak.v2](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/keycloak.v2)

Поддиректории внутри директории каждой из тем представляют собой различные наборы интерфейсов - **типов тем** - доступных для кастомизации:

- [account](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/keycloak.v2/account) - консоль аккаунта;
- [admin](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/base/admin) - административная консоль;
- [common](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/keycloak/common) - общие ресурсы, используемые всеми типами
  тем;
- [email](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/keycloak/email) - почта;
- [login](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/keycloak/login) - страницы логинов, включая страницы
  регистраций, обновления профилей и сброса паролей;

> Тип темы логина может быть определен не только для реалма, но и для клиента!

- [welcome](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/keycloak/welcome) - страницы приветствий.

> Тема welcome является особенной, т.к. она не относится ни к реалму, ни к клиенту.

Внутри каждого из типов тем находится обязательный
файл [theme.properties](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/keycloak/login/theme.properties), в котором
задана конфигурация для данного типа темы, например:

- наследование конфигурации из другой темы;
- импорт ресурсов из другой темы;
- пользовательские `CSS`;
- пользовательские `JS`;
- сопоставление пользовательских `CSS` со стилями, используемыми такими компонентами Keycloak, как поля ввода и кнопки.

Таким образом, не обязательно создавать собственную тему с нуля, можно унаследовать существующую тему и изменить только то, что нужно.

Тема оформления может быть определена не только для реалма, но и для клиента, но только для страниц логина. Настройка выполняется на
странице свойств клиента, закладка "Settings", раздел "Login Settings".

### Локализация

По умолчанию сообщения загружаются из файлов свойств, расположенных в
директориях [messages](applications/ch13/org.keycloak.keycloak-themes-22.0.0/theme/base/account/messages) соответствующих типов тем.
В качестве альтернативы, администратор может настроить сообщения через административную консоль.

---

## Пример программной установки темы

Пример реализации [Provider и ProviderFactory](theme-beijing/src/main/java/org/keycloak/book/ch13/theme/MyThemeSelectorProvider.java)
позволяет устанавливать тему через параметр URL `&theme=<ИмяТемы>`:

**Применение темы "Beijing":**

https://haproxy/realms/myrealm/protocol/openid-connect/auth?client_id=account-console&redirect_uri=https%3A%2F%2Fhaproxy%2Frealms%2Fmyrealm%2Faccount%2F%23%2F%3Ftheme%3DBeijing&state=89fcd033-fac2-440a-a0bd-f1241bc57d45&response_mode=fragment&response_type=code&scope=openid&nonce=f29a41b5-e67e-4127-a5bb-b912c99cadb5&code_challenge=a-NElf11f4Q5NB-ard8POp2sI1HZBqez8l7ik4kX4DI&code_challenge_method=S256&theme=Beijing

**Применение темы "tropicana":**

https://haproxy/realms/myrealm/protocol/openid-connect/auth?client_id=account-console&redirect_uri=https%3A%2F%2Fhaproxy%2Frealms%2Fmyrealm%2Faccount%2F%23%2F%3Ftheme%3DBeijing&state=89fcd033-fac2-440a-a0bd-f1241bc57d45&response_mode=fragment&response_type=code&scope=openid&nonce=f29a41b5-e67e-4127-a5bb-b912c99cadb5&code_challenge=a-NElf11f4Q5NB-ard8POp2sI1HZBqez8l7ik4kX4DI&code_challenge_method=S256&theme=tropicana

---

## Пример загрузки дополнительных шаблонов и любых ресурсов в тему

Пример реализации [Provider и ProviderFactory](theme-beijing/src/main/java/org/keycloak/book/ch13/theme/MyThemeResourceProvider.java).

---

# Защита Keycloak

Keycloak и его БД изолированы от пользователей и приложений с помощью Web Application Firewall (WAF), все сетевые запросы шифруются и БД
также зашифрована:

![SecuredKeycloak.jpg](img/ch14/1400_SecuredKeycloak.jpg)

Рекомендуется шифровать все коммуникации к Keycloak и от него.

Если перед Keycloak расположен балансировщик нагрузки или реверсный прокси, то самым безопасным будет использование сквозного TLS,
обеспечивающего сквозное шифрование между клиентом и Keycloak.

Если это невозможно, то следует использовать перешифровку (reencrypt), когда соединения между прокси и Keycloak повторно шифруются с
применением внутреннего сертификата.

Следует избегать применения незашифрованных соединений между прокси и Keycloak кроме случаев, когда сеть между ними является полностью
изолированной (например, если они работают на одной машине).

### Keycloak должен знать свой публичный хост

По умолчанию Keycloak получает имя хоста из заголовка `Host` HTTP-запроса, поступившего от клиента. Такой подход не следует применять в
промышленной среде, т.к. атакующий может прислать запрос с другим значением этого заголовка.

Такая подмена м.б. применена, например, с целью использовать для взлома функцию восстановления пароля Keycloak:

1. Злоумышленнику становится известен e-mail реального пользователя Keycloak;
2. Злоумышленник отправляет Keycloak запрос на обновление пароля для e-mail реально существующего пользователя, указав при этом в
   заголовке `Host` адрес сервера, контролируемого злоумышленником;
3. Keycloak получает такой запрос на обновление пароля с ложным значением `Host` и отправляет на e-mail реально существующего пользователя
   письмо с предложением обновить пароль;
4. Реально существующий пользователь, получив письмо на обновление пароля, нажимает ссылку, подтверждая обновление пароля;
5. Т.к. адрес хоста Keycloak изначально был подменён, то ссылка на обновление пароля уходит не на реальный адрес хоста Keycloak, а на
   адрес сервера злоумышленника;
6. Сервер злоумышленника получает запрос на обновление пароля, устанавливает в запросе свой пароль (или просто перехватывает пароль
   пользователя) и пересылает этот запрос на реальный хост Keycloak;
7. Keycloak получив запрос на обновление пароля устанавливает новый пароль, как действующий;
8. С этого момента пароль злоумышленника позволяет получить доступ к Keycloak.

Для предотвращения такого типа атак можно или задать фиксированное имя хоста для Keycloak, или, если Keycloak прикрыт реверсным прокси,
можно проверять заголовок `Host` на самом прокси.

### Ротация подписывающих ключей с использованием Keycloak

Настоятельно рекомендуется хотя бы раз в месяц ротировать все ключи подписи/шифрования.

Ротация:

- снижает количество контента, подписанного/зашифрованного конкретным ключом;
- снижает время на взлом конкретного ключа;
- очищает неиспользуемые токены обновления или долгоживущие токены доступа независимо от времени жизни сессии пользователя;
- снижает вред, который м.б. причинён в случае утечки токена.

Ключи в Keycloak могут находиться в **трех состояниях**:

- **Active**: ключ используется для подписания новых токенов, ключи с наивысшим приоритетом используются для указанного алгоритма;
- **Passive**: ключ не используются для подписания новых токенов, но используется для верификации ранее подписанных токенов;
- **Disabled**: ключ никак не используется.

> Если после создания нового активного ключа предыдущий ключ был отключен, то все активные сессии пользователей и токены будут
> инвалидированы!
>
> Такой подход полезен в случае, если есть подозрение, что ключ был скомпрометирован. В прочих случаях лучше переключить предыдущий ключ в
> пассивное состояние на период, достаточный, чтобы все пользовательские сессии и токены обновились с участием новых подписывающих
> ключей, и только потом удалять старый ключ.

### Создание нового ключа

Ротация выполняется созданием нового активного ключа. Realm Settings -> Keys -> Providers -> rsa-generated

1. Создать нового провайдера `rsa-generated`:

![1410_NewKey1.png](img/ch14/1410_NewKey1.png)

2. Установить более высокий приоритет, чем у существующего провайдера, чтобы Keycloak автоматически стал подписывать куки и токены новыми
   ключами:
   ![1410_NewKey2.png](img/ch14/1410_NewKey2.png)

3. Новый провайдер появится в списке провайдеров:

![1410_NewKey3.png](img/ch14/1410_NewKey3.png)

4. Новый ключ появится в списке ключей:

![1410_NewKey4.png](img/ch14/1410_NewKey4.png)

Приватные ключи по умолчанию хранятся в БД, но возможно хранение в Java Keystore, а также реализация кастомного хранилища через провайдеры.

## Регулярное обновление Keycloak

Keycloak не имеет LTS-версий, а используется модель скользящих выпусков (`rolling releases`), что позволяет быстро накатывать обновления,
которые имеют небольшой объём.

## Работа Keycloak с внешними хранилищами секретов

Keycloak имеет поддержку секретов Kubernetes/OpenShift, а также может использовать зашифрованный Java KeyStore.

Механизмы расширения Keycloak позволяют реализовать связь с любым внешним хранилищем.

## Защита Keycloak с помощью файрволла/бредмауэра/межсетевого экрана и системы предотвращения вторжений

Желательна защита входящего и исходящего трафикам Keycloak с помощью файрволла. Желательно вообще изолировать Keycloak и его БД даже от
внутренних приложений.

Для входящего трафика:

- принимать только HTTPS;
- доступ к административной консоли Keycloak и административным REST API только из внутренней сети.

Для исходящего трафика:

- разрешить backchannel-запросы (например, logout-запросы) по HTTPS к приложениям;
- разрешить подключение к поставщикам федеративных пользователей (например, LDAP);
- разрешить backchannel-запросы к внешним поставщиками удостоверения (например запросы токенов OpenID).

Если Keycloak защищает только внутренние приложения, то проще будет защитить только исходящий трафик. Если же Keycloak защищает сторонние
приложения, развернутые за пределами сети, то это более сложная задача.

Разумным будет использовать систему предотвращения вторжения или предупреждения о таковом. Это позволит обнаружить и заблокировать опасный
трафик, а также поможет в случае DNS-атаки (denial-of-service).

В качестве дополнительного средства безопасности можно использовать **WAF (Web Application Firewall)**, предотвращающий широкий спектр атак.

## Защита БД Keycloak

Keycloak хранить в БД большой объём чувствительной информации:

- конфигурации Realm;
- данные пользователей;
- данные клиентов.

Защищать следует не только саму БД, но и её резервные копии.

### Защита БД с помощью файрволла

Не должен пропускаться никакой трафик, кроме как от Keycloak-серверов.

Кроме того, должны быть закрыты все исходящие соединения, кроме явно необходимых.

### Включение аутентификации и контроля доступа к БД

Доступ к БД должны иметь минимальное количество сотрудников и их полномочия должны быть максимально ограничены. А т.к. Keycloak управляет не
только содержимым БД, но и её схемой, то следует задаться вопросом, нужен ли вообще кому-нибудь постоянный доступ к БД.

Пароли и Keycloak и пользователей должны быть сложными к взлому, а аккаунты должны блокироваться после неудачной попытки логина.

Возможно использование и более строгих механизмов аутентификации, таких как клиентские сертификаты.

### Шифрование БД

Для защиты пересылаемых данных все подключения к БД должны быть защифрованы с применением TLS (Transport Layer Security). Также следует
зашифровать сами хранящиеся данные, включая данные в резервных копиях.

## Защита кластерных коммуникаций

Keycloak имеет встроенный Infinispan, которые применяется при создании кластера из Keycloak-нод.

Чувствительные данные, такие как подписывающие ключи или пользовательская информация, внутри кластера не пересылаются - такая информация
содержится только в локальном кэше каждой ноды, внутри же кластера передаются только сообщения об инвалидации. Локальный кэш хранит
информацию о сессиях пользователей, распределенных по кластеру. Сами сессии содержат такую информацию, как ID сессии, время жизни сессии и
ассоциированные клиентские сессии. Даже если атакующий получает доступ к этой информации, то он ограничен в её использовании, т.к. доступ к
любой сессии через Keycloak требует токена или куки, подписанного через Keycloak.

Может быть хорошей идеей защитить кластерные коммуникации хотя бы файрволлом. Для дополнительной защиты можно подключить аутентификацию
и/или шифрование кластерной коммуникации.

### Включение кластерной аутентификации

Кластерная аутентификация исключает подключение неавторизованных нод к кластеру, но не предотвращает коммуникацию между участниками кластера
с неучастниками кластера. По этой причине сама по себе кластерная аутентификация не имеет особого смысла и должна комбинироваться с
асимметричным шифрованием.

### Шифрование кластерной аутентификации

Кластерная коммуникация м.б. зашифрована или с помощью симметричного или асимметричного шифрования. Простейшим подходом является
использование симметричного шифрования.

1. Создать Java Keystore для хранения секрета:

```bash
$ keytool -genseckey -alias myKey -keyalg aes -keysize 128 -keystore myKeystore.p12 -storetype PKCS12 -storepass changeit -keypass changeit                                                                                                                                                                                                                              main|✚1 ✭1⚑1
Generated 128-bit AES secret key
```

Созданный файл [myKeystore.p12](applications/ch14/myKeystore.p12) следует скопировать во все ноды Keycloak.

2. В файле `conf/cache-ispn.xml` перед тегом `<cache-container>` вставить следующий элемент:

```xml

<jgroups>
    <stack name="encrypt-udp" extends="udp">
        <SYM_ENCRYPT keystore_name="myKeystore.p12"
                     keystore_type="PKCS12"
                     store_password="changeit"
                     key_password="changeit"
                     alias="myKey"
                     stack.combine="INSERT_AFTER"
                     stack.position="VERIFY_SUSPECT2"/>
    </stack>
</jgroups>
```

Это добавит новый кэш-стек, расширяющий дефолтный udp-стек добавляя поддержку симметричного шифрования в созданное хранилище ключей.

```xml

<transport lock-timeout="60000" stack="encrypt-udp"/>
```

Файл `conf/cache-ispn.xml` также должен быть модифицирован на всех нодах Keycloak.

> Следует указать использование конфигурационного файла в опции `cache-configuration-file`.

Для проверки того, что шифрование работает, можно или запустить одну Keycloak ноду с включённым шифрованием, а другую - без, или попытаться
использовать на одной ноде отличающееся хранилище ключей. При попытке такой ноды присоединиться к кластеру получим ошибку:

> ERROR [org.jgroups.protocols.SYM_ENCRYPT] (jgroups-8,fedora-30300) fedora-30300:
> rejected decryption of unicast message from non-member fedora-23997

Это означает, что ноде не было разрешено присоединиться к кластеру, а также читать или отправлять сообщения в кластер.

## Защита пользовательских аккаунтов

Достигается применением более строгой аутентификации, чем просто защита паролем. Пароль д.б. защищен даже при использовании двухфакторной
аутентификации.

Пароли защищаются применением сильного алгоритма хэширования паролей, надежной политикой в отношении паролей и включением защиты от
прямого перебора (brute-force). Также важно понимание пользователями важности применять сильные пароли и не использовать пароли от других
сервисов.

Политика в отношении паролей настраивается в настройках реалма `Authentication` -> `Policies`, закладка `Password Policy`:

![1420_PasswordPolicy.png](img/ch14/1420_PasswordPolicy.png)

Пример политики, при которой пароль должен иметь не менее 8 символов, содержать 1 специальный символ и 1 символ в верхнем регистре:

![1421_PasswordPolicy.png](img/ch14/1421_PasswordPolicy.png)

Защита от прямого перебора (brute-force) подключается в настройках реалма `Realm Settings` -> `Security defences`, закладка
`Brute force detection`:

![1422_BruteForceProtection.png](img/ch14/1422_BruteForceProtection.png)

## Защита приложений

Основным подходом является использование файрволлов и VPN в качестве главного слоя защиты от атак.
Это комбинируется с периметром безопасности самого предприятия. Но проблема усугубляется массовым переходом персонала на удалённый режим
работы, а также массовым открытием сервисов для партнёров или для публичного доступа, размывая тем самым периметр безопасности.

Сама идея доверять всему, что находится внутри предприятия и не доверять тому, что снаружи, оказывается под вопросом, т.к. атакующий может
действовать и из внутренней сети.

Соответственно, нужно что-то большее, чем просто файрволл и Keycloak здесь оказывается отличным средством, но при этом само приложение не
становится безопасным просто из-за использования Keycloak - здесь требуются отдельные мероприятия.

### Защита веб-приложений

- **Аутентификация** - для аутентификации подходит Keycloak, но при этом важно обеспечить безопасность самой сессии.
- **Авторизация** - принцип минимальных полномочий позволяет снизить последствия атаки.
- **Защита от общераспространенных атак** - приложение должно иметь стандартные механизмы защиты (например, от Cross-Site Scripting, XSS).
- **Регулярные обновления** - обеспечение безопасности - это непрерывная работа, включая обновление фреймворков, библиотек и прочего.
- **Безопасность данных** - чувствительные данные д.б. зашифрованы, включая пересылку и резервные копии. Доступ к таким данным также должен
  требовать аутентификации и авторизации.
- **Логирование и мониторинг** - своевременное обнаружение атаки или компрометации данных позволяет уменьшить ущерб.
- **Файрволл и WAF** - являются дополнительным слоем защиты.

Ресурсы по актуальным угрозам безопасности:

- [Open Web Application Security Project (OWASP) Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Применение OAuth 2.0 и OpenID connect

Спецификации OAuth 2.0 и OpenID Connect имеют значительную гибкость в использовании и много механизмов для защиты от уязвимостей.
Но простой авторизационный запрос не имеет ни параметра `state`, ни параметра `nonce`. Также не используется PKCE (Proof Key for Code
Exchange):

```bash
/auth?response_type=code&client_id=public-client&redirect_uri=https://acme.corp/myclient
```

Такой запрос открыт к нескольким известным уязвимостям.

Аналогичная проблема существует и у спецификации JWT (JSON Web Token). Например, включенный в спецификацию параметр `none` для алгоритма
позволяет указать, что алгоритм подписания не используется, и это создаёт возможность для атакующего создавать собственные токены.

Ресурсы по безопасности [OAuth 2.0](https://oauth.net/2/):

- OAuth 2.0 for mobile and native apps;
- OAuth 2.0 for browser-based apps;
- OAuth 2.0 threat model and security considerations;
- OAuth 2.0 security best current practice;
- The OAuth 2.1 Authorization Framework;

Спецификация OAuth 2.1 содержит описание нескольких практик, что упрощает задачу защиты путем простого соблюдения спецификации.

Рабочая группа FAPI (Financial-Grade API) возникла в результате создания высокозащищенных профилей OIDC с целью использования OIDC для
открытого банкинга.
Группа предложила два профиля с лучшими подходами:

- **FAPI 1.0 – Part 1: Baseline API Security Profile**
- **FAPI 1.0 – Part 2: Advanced Security Profile**

Сама команда Keycloak также постоянно работает над улучшением практик использования OAuth 2.0 и OpenID Connect в приложениях.
Важным улучшением является введение функции клиентских политик. С помощью клиентских политик легко обеспечить использование лучших практик
для приложений, включая выбор различных профилей в зависимости от необходимого уровня безопасности.

### Конфигурации OIDC-клиента Keycloak

- `Consent required` - если выключено, то пользователь не увидит, какой уровень доступа получает приложение. Для любого стороннего
  приложения
  эту опцию следует включить. Также включить для нативных приложений (например, для CLI).
- `Client authentication` - более безопасно включить эту опцию если учетные записи клиента могут безопасно храниться на стороне сервера.
- `Standard flow` - подключает клиенту процесс авторизационного кода.
- `Implicit flow` - подключает ныне устаревший `Implicit flow`. Следует включать только при полной необходимости и отключить после
  обновления
  приложения.
- `Direct access grants` - подключает ныне устаревший пароль собственника ресурсов. Следует включать только при полной необходимости и
  отключить после обновления приложения.
- `Valid redirect URIs` - рекомендуется использовать точно совпадающий URL, хотя Keycloak и поддерживает шаблоны.

#### Алгоритмы подписания, поддерживаемые Keycloak:

- `Rivest–Shamir–Adleman (RSA) signature` - дефолтный алгоритм, не самый безопасный, но самый распространённый;
- `Elliptic Curve Digital Signature Algorithm (ECDSA)` - более безопасный, чем RSA, но гораздо более быстрый. По возможности, следует
  предпочесть `ECDSA` вместо `RSA, хотя `RSA` по-прежнему считается безопасным;
- `Hash-based message authentication code (HMAC)` - алгоритм с симметричным подписанием, требующий доступа к общему секрету. Если требуется
  принудить приложения использовать точку доступа интроспекции токенов для верификации токена, то можно использовать `HMAC` в качестве
  секрета. Это доступно только для Keycloak.

Также можно изменять длину подписывающих хэшей - более длинных хэш даёт большую безопасность. Для короткоживущих токенов, таких как
`Access Token` и `Refresh Token`, длина в 256 бит считается более чем достаточной.

Другим важным параметром является время жизни токенов и сессий. Keycloak позволяет конфигурировать время жизни `Access Token`-ов для каждого
клиента. Также можно изменять время жизни сессий, что позволяет управлять временем жизни `Refresh Token`-ов. Всё это позволяет иметь
относительно длительное время существования SSO-сессии (дни или даже недели), при коротком времени жизни `Refresh Token`-ов (меньше часа).
Короткое время жизни `Refresh Token`-ов смягчает последствия их утечки и сокращает время жизни HTTP-сессий приложения.

---

02.12.2024 г.