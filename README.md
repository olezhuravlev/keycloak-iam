### How to export a realm

1. Login to the Docker container shell:

```shell
$ docker exec -it keycloak bash
```

2. Proceed to the Keycloak directory `/opt/keycloak/bin`;

3. Run export procedure `./kc.sh export --file <FILE_NAME> --realm <REALM_NAME>`:

```shell
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

```shell
$ sudo find / -name "realm-myrealm-exported.json" -type f
/var/snap/docker/common/var-lib-docker/overlay2/.../diff/opt/keycloak/bin/realm-myrealm-exported.json
```

It's a sudo directory so copy the file to the accessible location:

```shell
$ sudo cp /var/snap/docker/common/var-lib-docker/overlay2/10208ebe783a5c88abdd50a8b9503c5c9dc812c05016f17758af4edcff6ebcdb/diff/opt/keycloak/bin/realm-myrealm-exported.json /home/oleg/MyProjects/keycloak-iam/keycloak/config
```

And change the access:

```shell
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

## Процедура авторизации "ID Connect"

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

## OAuth 2.0 - индустриальный стандарт протокола авторизации (но не аутентификации!)

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

> Называется `Relying Party` ("доверяющая сторона"), поскольку это сторона, которая полагается на OpenID Provider (OP) для проверки личности
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

#### Процесс аутентификации OIDC (OpenID Connect)

1. Приложение создаёт `Authentication request`, перенаправляющий браузер пользователя на Keycloak;
2. Браузер пользователя переходит на `Authorization Endpoint` Keycloak;
3. Если пользователь еще не аутентифицирован на Keycloak, то Keycloak его аутентифицирует;
4. Приложение получает от Keycloak `Authentication Response`, содержащий в себе `Authorization Code`;
5. Приложение выполняет `Token Request` к `Token Endpoint` Keycloak для обмена полученного `Authorization Code` на два токена - `ID Token`
   и `Access Token`;
6. Обладая `ID token` приложение может идентифицировать личность пользователя и установить для него аутентифицированную сессию.

![openid_connect_auth_code_flow.jpg](img/openid_connect_auth_code_flow.jpg)

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

Зрелый протокол (ратифицирован как `OASIS Standard` с 2005г.), широко используемый для реализации `SSO (Single Sign-On)` в корпоративных системах, включая их
SAAS-реализации.

По сравнению с `SAML 2.0` протокол `OIDC` проще в понимании за счет использования JSON и простых параметров запросов.

Кроме того, `OIDC` более сфокусирован на современных архитектурах, как SPA (Single-Page Application), мобильных приложениях, REST
API и микросервисах.

#### Keycloak позволяет использовать оба протокола - и `SAML 2.0` и `OIDC`!

---


