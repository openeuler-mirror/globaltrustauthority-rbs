<!-- Generator: Widdershins v4.0.1 -->

<h1 id="rbs-rest-api">RBS REST API v0</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

Resource Broker Service (RBS) HTTP API.

Base URLs:

* <a href="http://localhost:6666">http://localhost:6666</a>

Web: <a href="https://gitcode.com/openeuler/globaltrustauthority-rbs">RBS open-source community</a> 
License: <a href="http://license.coscl.org.cn/MulanPSL2">Mulan Permissive Software License, Version 2</a>

# Authentication

- HTTP Authentication, scheme: bearer Attest token. Send as `Authorization: Attest <token>`. Obtain via `POST /rbs/v0/attest`.

- HTTP Authentication, scheme: bearer JWT Bearer token. Send as `Authorization: Bearer <token>`. Obtain via Admin API or attestation.

<h1 id="rbs-rest-api-system">System</h1>

`RbsCore::system` — service identity and API/build version via `GET /rbs/version` (system metadata). Does not require authentication.

## rbsVersion

<a id="opIdrbsVersion"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/version \
  -H 'Accept: application/json'

```

```http
GET http://localhost:6666/rbs/version HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json'
};

fetch('http://localhost:6666/rbs/version',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json'
}

result = RestClient.get 'http://localhost:6666/rbs/version',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json'
}

r = requests.get('http://localhost:6666/rbs/version', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/version', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/version");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/version", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/version`

*Get service name, API version, and build metadata*

> Example responses

> 200 Response

```json
{
  "service_name": "globaltrustauthority-rbs",
  "api_version": "0",
  "build": {
    "version": "0.1.0",
    "git_hash": "",
    "build_date": ""
  }
}
```

<h3 id="rbsversion-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Version payload: service name, API contract version, and build metadata (JSON).|[RbsVersion](#schemarbsversion)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None
</aside>

<h1 id="rbs-rest-api-admin">Admin</h1>

User management CRUD — `GET/POST/PUT/DELETE /rbs/v0/users` (admin or self). Requires BearerToken.

## listUsers

<a id="opIdlistUsers"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/users \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/users HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/users',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/users',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/users', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/users', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/users");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/users", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/users`

*List users (admin only)*

<h3 id="listusers-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|limit|query|integer(int64)|false|Page size (1..100, default 10)|
|offset|query|integer(int64)|false|Offset (0..100000, default 0)|
|role|query|[Role](#schemarole)|false|Filter by role (admin or user)|
|enabled|query|boolean|false|Filter by enabled status|

#### Enumerated Values

|Parameter|Value|
|---|---|
|role|admin|
|role|user|

> Example responses

> 200 Response

```json
{
  "users": [
    {
      "id": "string",
      "username": "string",
      "role": "admin",
      "enabled": true,
      "created_at": "string",
      "updated_at": "string"
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

<h3 id="listusers-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Paginated user list|[UserListResponse](#schemauserlistresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## createUser

<a id="opIdcreateUser"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/users \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
POST http://localhost:6666/rbs/v0/users HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "username": "string",
  "role": {},
  "enabled": true,
  "auth_type": "jwt",
  "public_key": "string",
  "jwk": null
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/users',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/users',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.post('http://localhost:6666/rbs/v0/users', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/users', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/users");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/users", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/users`

*Create a user (admin only)*

> Body parameter

```json
{
  "username": "string",
  "role": {},
  "enabled": true,
  "auth_type": "jwt",
  "public_key": "string",
  "jwk": null
}
```

<h3 id="createuser-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[UserCreateRequest](#schemausercreaterequest)|true|none|

> Example responses

> 201 Response

```json
{
  "id": "string",
  "username": "string",
  "role": "admin",
  "enabled": true,
  "created_at": "string",
  "updated_at": "string"
}
```

<h3 id="createuser-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|User created|[UserResponse](#schemauserresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Invalid request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|409|[Conflict](https://tools.ietf.org/html/rfc7231#section-6.5.8)|Username already exists|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## getUser

<a id="opIdgetUser"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/users/{username} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/users/{username} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/users/{username}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/users/{username}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/users/{username}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/users/{username}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/users/{username}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/users/{username}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/users/{username}`

*Get a user (admin or self)*

<h3 id="getuser-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|username|path|string|true|Username|

> Example responses

> 200 Response

```json
{
  "id": "string",
  "username": "string",
  "role": "admin",
  "enabled": true,
  "created_at": "string",
  "updated_at": "string"
}
```

<h3 id="getuser-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|User found|[UserResponse](#schemauserresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|User not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## updateUser

<a id="opIdupdateUser"></a>

> Code samples

```shell
# You can also use wget
curl -X PUT http://localhost:6666/rbs/v0/users/{username} \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
PUT http://localhost:6666/rbs/v0/users/{username} HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "role": {},
  "enabled": true,
  "auth_type": {},
  "public_key": "string",
  "jwk": null
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/users/{username}',
{
  method: 'PUT',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.put 'http://localhost:6666/rbs/v0/users/{username}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.put('http://localhost:6666/rbs/v0/users/{username}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('PUT','http://localhost:6666/rbs/v0/users/{username}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/users/{username}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("PUT");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("PUT", "http://localhost:6666/rbs/v0/users/{username}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`PUT /rbs/v0/users/{username}`

*Update a user (admin or self)*

> Body parameter

```json
{
  "role": {},
  "enabled": true,
  "auth_type": {},
  "public_key": "string",
  "jwk": null
}
```

<h3 id="updateuser-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|username|path|string|true|Username|
|body|body|[UserUpdateRequest](#schemauserupdaterequest)|true|none|

> Example responses

> 200 Response

```json
{
  "id": "string",
  "username": "string",
  "role": "admin",
  "enabled": true,
  "created_at": "string",
  "updated_at": "string"
}
```

<h3 id="updateuser-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|User updated|[UserResponse](#schemauserresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Invalid request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden — caller is neither admin nor self; a non-admin self-update attempted to change `role`/`enabled`; an attempt to modify the built-in Administrator's `role`/`enabled`; or an attempt to assign the `admin` role (pre-configured, no-op on the built-in admin only)|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|User not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteUser

<a id="opIddeleteUser"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/users/{username} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/users/{username} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/users/{username}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/users/{username}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/users/{username}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/users/{username}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/users/{username}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/users/{username}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/users/{username}`

*Delete a user (admin only)*

<h3 id="deleteuser-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|username|path|string|true|Username|

> Example responses

> 401 Response

```json
{
  "error": "string"
}
```

<h3 id="deleteuser-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|User deleted (no body)|None|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|User not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

<h1 id="rbs-rest-api-policy">Policy</h1>

Policy CRUD — `GET/POST/PUT/DELETE /rbs/v0/resource/policy`. Requires BearerToken.

## listPolicies

<a id="opIdlistPolicies"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/resource/policy \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/resource/policy HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/resource/policy',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/resource/policy',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/resource/policy', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/resource/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/resource/policy");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/resource/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/resource/policy`

*List policies*

<h3 id="listpolicies-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|ids|query|string|false|Comma-separated policy IDs|
|limit|query|integer(int64)|false|Page size (1..100, default 10)|
|offset|query|integer(int64)|false|Offset (0..100000, default 0)|

> Example responses

> 200 Response

```json
{
  "items": [
    {
      "policy_id": "string",
      "policy_name": "string",
      "policy_version": 0,
      "content_type": "string",
      "created_at": "string",
      "updated_at": "string",
      "applied_resources": [
        "string"
      ]
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

<h3 id="listpolicies-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Policy list|[PolicyListResponse](#schemapolicylistresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## createPolicy

<a id="opIdcreatePolicy"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/resource/policy \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
POST http://localhost:6666/rbs/v0/resource/policy HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "name": "string",
  "content_type": "string",
  "content": "string"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/resource/policy',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/resource/policy',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.post('http://localhost:6666/rbs/v0/resource/policy', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/resource/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/resource/policy");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/resource/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/resource/policy`

*Create a policy*

> Body parameter

```json
{
  "name": "string",
  "content_type": "string",
  "content": "string"
}
```

<h3 id="createpolicy-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[CreatePolicyRequest](#schemacreatepolicyrequest)|true|none|

> Example responses

> 201 Response

```json
{
  "policy_id": "string",
  "policy_name": "string",
  "policy_version": 0,
  "content_type": "string",
  "created_at": "string",
  "updated_at": "string",
  "applied_resources": [
    "string"
  ]
}
```

<h3 id="createpolicy-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Policy created|[PolicyResponse](#schemapolicyresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|409|[Conflict](https://tools.ietf.org/html/rfc7231#section-6.5.8)|Conflict (name duplicate / count exceeded)|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## batchDeletePolicies

<a id="opIdbatchDeletePolicies"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/resource/policy?ids=string \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/resource/policy?ids=string HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/resource/policy?ids=string',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/resource/policy',
  params: {
  'ids' => 'string'
}, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/resource/policy', params={
  'ids': 'string'
}, headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/resource/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/resource/policy?ids=string");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/resource/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/resource/policy`

*Batch delete policies*

<h3 id="batchdeletepolicies-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|ids|query|string|true|Comma-separated policy IDs (maximum 10 IDs)|

> Example responses

> 400 Response

```json
{
  "error": "string"
}
```

<h3 id="batchdeletepolicies-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Policies deleted|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|409|[Conflict](https://tools.ietf.org/html/rfc7231#section-6.5.8)|Policy is referenced by resources|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## getPolicy

<a id="opIdgetPolicy"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/resource/policy/{policy_id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/resource/policy/{policy_id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/resource/policy/{policy_id}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/resource/policy/{policy_id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/resource/policy/{policy_id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/resource/policy/{policy_id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/resource/policy/{policy_id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/resource/policy/{policy_id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/resource/policy/{policy_id}`

*Get policy detail*

<h3 id="getpolicy-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|policy_id|path|string|true|Policy ID|

> Example responses

> 200 Response

```json
{
  "policy_id": "string",
  "policy_name": "string",
  "policy_version": 0,
  "content_type": "string",
  "created_at": "string",
  "updated_at": "string",
  "applied_resources": [
    "string"
  ]
}
```

<h3 id="getpolicy-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Policy detail|[PolicyResponse](#schemapolicyresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## updatePolicy

<a id="opIdupdatePolicy"></a>

> Code samples

```shell
# You can also use wget
curl -X PUT http://localhost:6666/rbs/v0/resource/policy/{policy_id} \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
PUT http://localhost:6666/rbs/v0/resource/policy/{policy_id} HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "name": "string",
  "content_type": "string",
  "content": "string"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/resource/policy/{policy_id}',
{
  method: 'PUT',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.put 'http://localhost:6666/rbs/v0/resource/policy/{policy_id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.put('http://localhost:6666/rbs/v0/resource/policy/{policy_id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('PUT','http://localhost:6666/rbs/v0/resource/policy/{policy_id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/resource/policy/{policy_id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("PUT");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("PUT", "http://localhost:6666/rbs/v0/resource/policy/{policy_id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`PUT /rbs/v0/resource/policy/{policy_id}`

*Update a policy*

> Body parameter

```json
{
  "name": "string",
  "content_type": "string",
  "content": "string"
}
```

<h3 id="updatepolicy-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|policy_id|path|string|true|Policy ID|
|body|body|[UpdatePolicyRequest](#schemaupdatepolicyrequest)|true|none|

> Example responses

> 200 Response

```json
{
  "policy_id": "string",
  "policy_name": "string",
  "policy_version": 0,
  "content_type": "string",
  "created_at": "string",
  "updated_at": "string",
  "applied_resources": [
    "string"
  ]
}
```

<h3 id="updatepolicy-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Policy updated|[PolicyResponse](#schemapolicyresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|409|[Conflict](https://tools.ietf.org/html/rfc7231#section-6.5.8)|Version conflict|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deletePolicy

<a id="opIddeletePolicy"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/resource/policy/{policy_id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/resource/policy/{policy_id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/resource/policy/{policy_id}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/resource/policy/{policy_id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/resource/policy/{policy_id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/resource/policy/{policy_id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/resource/policy/{policy_id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/resource/policy/{policy_id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/resource/policy/{policy_id}`

*Delete a policy*

<h3 id="deletepolicy-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|policy_id|path|string|true|Policy ID|

> Example responses

> 401 Response

```json
{
  "error": "string"
}
```

<h3 id="deletepolicy-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Policy deleted|None|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|409|[Conflict](https://tools.ietf.org/html/rfc7231#section-6.5.8)|Policy is referenced by resources|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

<h1 id="rbs-rest-api-resource">Resource</h1>

Resource CRUD — `GET/POST/PUT/DELETE /rbs/v0/{provider}/{repo}/{type}/{name}`. Supports AttestToken and BearerToken.

## getResource

<a id="opIdgetResource"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}`

*Get resource content*

<h3 id="getresource-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|res_provider|path|string|true|Resource provider name|
|repository_name|path|string|true|Repository name|
|resource_type|path|string|true|Resource type (secret, cert, etc.)|
|resource_name|path|string|true|Resource name|

> Example responses

> 200 Response

```json
{
  "uri": "string",
  "content": "string",
  "content_type": "string",
  "export_mode": "string"
}
```

<h3 id="getresource-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Resource content (base64-encoded JWE)|[ResourceContentResponse](#schemaresourcecontentresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Resource not found or access denied|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth, attestAuth
</aside>

## updateResource

<a id="opIdupdateResource"></a>

> Code samples

```shell
# You can also use wget
curl -X PUT http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name} \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
PUT http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name} HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "policy_id": "string",
  "content_type": "string",
  "export_mode": "string",
  "additional_info": "string"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}',
{
  method: 'PUT',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.put 'http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.put('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('PUT','http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("PUT");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("PUT", "http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`PUT /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}`

*Update or create resource*

> Body parameter

```json
{
  "policy_id": "string",
  "content_type": "string",
  "export_mode": "string",
  "additional_info": "string"
}
```

<h3 id="updateresource-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|res_provider|path|string|true|Resource provider name|
|repository_name|path|string|true|Repository name|
|resource_type|path|string|true|Resource type (secret, cert, etc.)|
|resource_name|path|string|true|Resource name|
|body|body|[UpdateResourceRequest](#schemaupdateresourcerequest)|true|none|

> Example responses

> 200 Response

```json
{
  "uri": "string",
  "provider_name": "string",
  "repository_name": "string",
  "resource_type": "string",
  "resource_name": "string",
  "created_at": "string",
  "updated_at": "string",
  "content_type": "string",
  "export_mode": "string",
  "policy_id": "string",
  "additional_info": "string"
}
```

<h3 id="updateresource-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Resource updated|[ResourceResponse](#schemaresourceresponse)|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Resource created|[ResourceResponse](#schemaresourceresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|409|[Conflict](https://tools.ietf.org/html/rfc7231#section-6.5.8)|Conflict (version conflict / resource already exists / count exceeded)|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## createResource

<a id="opIdcreateResource"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name} \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
POST http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name} HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "policy_id": "string",
  "content_type": "string",
  "export_mode": "string",
  "additional_info": "string"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.post('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}`

*Create resource*

> Body parameter

```json
{
  "policy_id": "string",
  "content_type": "string",
  "export_mode": "string",
  "additional_info": "string"
}
```

<h3 id="createresource-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|res_provider|path|string|true|Resource provider name|
|repository_name|path|string|true|Repository name|
|resource_type|path|string|true|Resource type (secret, cert, etc.)|
|resource_name|path|string|true|Resource name|
|body|body|[CreateResourceRequest](#schemacreateresourcerequest)|true|none|

> Example responses

> 201 Response

```json
{
  "uri": "string",
  "provider_name": "string",
  "repository_name": "string",
  "resource_type": "string",
  "resource_name": "string",
  "created_at": "string",
  "updated_at": "string",
  "content_type": "string",
  "export_mode": "string",
  "policy_id": "string",
  "additional_info": "string"
}
```

<h3 id="createresource-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Resource created|[ResourceResponse](#schemaresourceresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|409|[Conflict](https://tools.ietf.org/html/rfc7231#section-6.5.8)|Conflict (resource already exists / count exceeded)|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteResource

<a id="opIddeleteResource"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}`

*Delete resource*

<h3 id="deleteresource-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|res_provider|path|string|true|Resource provider name|
|repository_name|path|string|true|Repository name|
|resource_type|path|string|true|Resource type (secret, cert, etc.)|
|resource_name|path|string|true|Resource name|

> Example responses

> 401 Response

```json
{
  "error": "string"
}
```

<h3 id="deleteresource-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Resource deleted|None|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Resource not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## getResourceInfo

<a id="opIdgetResourceInfo"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info`

*Get resource metadata*

<h3 id="getresourceinfo-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|res_provider|path|string|true|Resource provider name|
|repository_name|path|string|true|Repository name|
|resource_type|path|string|true|Resource type (secret, cert, etc.)|
|resource_name|path|string|true|Resource name|

> Example responses

> 200 Response

```json
{
  "uri": "string",
  "provider_name": "string",
  "repository_name": "string",
  "resource_type": "string",
  "resource_name": "string",
  "created_at": "string",
  "updated_at": "string",
  "content_type": "string",
  "export_mode": "string",
  "policy_id": "string",
  "additional_info": "string"
}
```

<h3 id="getresourceinfo-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Resource metadata|[ResourceResponse](#schemaresourceresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Resource not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth, attestAuth
</aside>

## retrieveResource

<a id="opIdretrieveResource"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve \
  -H 'Accept: application/json'

```

```http
POST http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json'
};

fetch('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve',
{
  method: 'POST',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json'
}

r = requests.post('http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve`

*Retrieve resource with attestation evidence*

The client submits RBC evidences in the request body. The service calls the
configured attestation backend to verify the evidence and obtain an attest
token, then uses the token claims (including `tee-pubkey`) for Rego policy
evaluation and JWE encryption of the resource content.

<h3 id="retrieveresource-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|res_provider|path|string|true|Resource provider name|
|repository_name|path|string|true|Repository name|
|resource_type|path|string|true|Resource type (secret, cert, etc.)|
|resource_name|path|string|true|Resource name|

> Example responses

> 200 Response

```json
{
  "uri": "string",
  "content": "string",
  "content_type": "string",
  "export_mode": "string"
}
```

<h3 id="retrieveresource-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Resource content (base64-encoded JWE)|[ResourceContentResponse](#schemaresourcecontentresponse)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Resource not found or access denied|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|502|[Bad Gateway](https://tools.ietf.org/html/rfc7231#section-6.6.3)|Attestation backend returned a non-2xx; RBS forwards GTA's status code and wraps GTA's body in the error field.|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|Attestation provider unreachable or timed out.|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None
</aside>

<h1 id="rbs-rest-api-attestation">Attestation</h1>

Attestation challenge/token issuance (`GET /rbs/v0/challenge`, `POST /rbs/v0/attest`, no auth) and attestation management CRUD for ref_value/cert/policy (`/rbs/v0/attestation/{as_provider}/{type}`, Bearer + admin only).

## postAttest

<a id="opIdpostAttest"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/attest \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json'

```

```http
POST http://localhost:6666/rbs/v0/attest HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "as_provider": "string",
  "rbc_evidences": {
    "agent_version": "string",
    "measurements": [
      {
        "nonce": "string",
        "node_id": "string",
        "nonce_type": "string",
        "token_fmt": "string",
        "attester_data": {},
        "evidences": [
          {
            "attester_type": "string",
            "evidence": null,
            "policy_ids": [
              "string"
            ],
            "ref_value_id": "string"
          }
        ]
      }
    ]
  }
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json'
};

fetch('http://localhost:6666/rbs/v0/attest',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/attest',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json'
}

r = requests.post('http://localhost:6666/rbs/v0/attest', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/attest', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attest");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/attest", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/attest`

*Submit attestation evidence and obtain token*

> Body parameter

```json
{
  "as_provider": "string",
  "rbc_evidences": {
    "agent_version": "string",
    "measurements": [
      {
        "nonce": "string",
        "node_id": "string",
        "nonce_type": "string",
        "token_fmt": "string",
        "attester_data": {},
        "evidences": [
          {
            "attester_type": "string",
            "evidence": null,
            "policy_ids": [
              "string"
            ],
            "ref_value_id": "string"
          }
        ]
      }
    ]
  }
}
```

<h3 id="postattest-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[AttestRequest](#schemaattestrequest)|true|none|

> Example responses

> 200 Response

```json
{
  "token": "string"
}
```

<h3 id="postattest-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Attestation token (JSON).|[AttestResponse](#schemaattestresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Invalid request.|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal server error.|[ErrorBody](#schemaerrorbody)|
|502|[Bad Gateway](https://tools.ietf.org/html/rfc7231#section-6.6.3)|Attestation backend returned a non-2xx; RBS forwards GTA's status code and wraps GTA's body in the error field.|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|Attestation provider unreachable or timed out.|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None
</aside>

## listCertsDefault

<a id="opIdlistCertsDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/cert \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/cert HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/cert',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/cert',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/cert', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/cert', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/cert");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/cert", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/cert`

*List certificates (default provider)*

<h3 id="listcertsdefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|ids|query|string|false|Comma-separated certificate IDs|
|cert_type|query|string|false|Filter by certificate type|
|limit|query|integer(int64)|false|Page size (1-10, default 10)|
|offset|query|integer(int64)|false|Offset (0-100000, default 0)|

> Example responses

> 200 Response

```json
{
  "certs": [
    {
      "cert_id": "C1",
      "cert_name": "cert1",
      "description": "string",
      "content": "string",
      "cert_type": [
        "string"
      ],
      "is_default": true,
      "version": 1,
      "create_time": 1700000000,
      "update_time": 1700000000,
      "valid_code": 0,
      "cert_revoked_date": 1700000000,
      "cert_revoked_reason": "string"
    }
  ],
  "crls": [
    {
      "crl_id": "L1",
      "crl_name": "crl1",
      "crl_content": "string"
    }
  ],
  "total_count": 0
}
```

<h3 id="listcertsdefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Certificate list|[CertListResponse](#schemacertlistresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## updateCertDefault

<a id="opIdupdateCertDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X PUT http://localhost:6666/rbs/v0/attestation/cert \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
PUT http://localhost:6666/rbs/v0/attestation/cert HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "id": "C1",
  "name": "string",
  "description": "string",
  "type": [
    "string"
  ],
  "content": "string",
  "is_default": true
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/cert',
{
  method: 'PUT',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.put 'http://localhost:6666/rbs/v0/attestation/cert',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.put('http://localhost:6666/rbs/v0/attestation/cert', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('PUT','http://localhost:6666/rbs/v0/attestation/cert', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/cert");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("PUT");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("PUT", "http://localhost:6666/rbs/v0/attestation/cert", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`PUT /rbs/v0/attestation/cert`

*Update a certificate (default provider)*

> Body parameter

```json
{
  "id": "C1",
  "name": "string",
  "description": "string",
  "type": [
    "string"
  ],
  "content": "string",
  "is_default": true
}
```

<h3 id="updatecertdefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[CertUpdateRequest](#schemacertupdaterequest)|true|none|

> Example responses

> 200 Response

```json
{
  "cert": {},
  "crl": {}
}
```

<h3 id="updatecertdefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Certificate updated|[CertMutationResponse](#schemacertmutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## createCertDefault

<a id="opIdcreateCertDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/attestation/cert \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
POST http://localhost:6666/rbs/v0/attestation/cert HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "name": "cert1",
  "type": "[\"tpm\"]",
  "description": "string",
  "content": "string",
  "crl_content": "string",
  "is_default": true
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/cert',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/attestation/cert',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.post('http://localhost:6666/rbs/v0/attestation/cert', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/attestation/cert', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/cert");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/attestation/cert", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/attestation/cert`

*Create a certificate (default provider)*

> Body parameter

```json
{
  "name": "cert1",
  "type": "[\"tpm\"]",
  "description": "string",
  "content": "string",
  "crl_content": "string",
  "is_default": true
}
```

<h3 id="createcertdefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[CertCreateRequest](#schemacertcreaterequest)|true|none|

> Example responses

> 201 Response

```json
{
  "cert": {},
  "crl": {}
}
```

<h3 id="createcertdefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Certificate created|[CertMutationResponse](#schemacertmutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteCertsDefault

<a id="opIddeleteCertsDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/cert \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/cert HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "type": "refvalue"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/cert',
{
  method: 'DELETE',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/cert',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/cert', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/cert', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/cert");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/cert", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/cert`

*Batch delete certificates (default provider)*

> Body parameter

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "type": "refvalue"
}
```

<h3 id="deletecertsdefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[CertDeleteRequest](#schemacertdeleterequest)|true|none|

> Example responses

> 400 Response

```json
{
  "error": "string"
}
```

<h3 id="deletecertsdefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Certificates deleted|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## getCertDefault

<a id="opIdgetCertDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/cert/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/cert/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/cert/{id}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/cert/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/cert/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/cert/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/cert/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/cert/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/cert/{id}`

*Get a single certificate (default provider)*

<h3 id="getcertdefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|id|path|string|true|Certificate or CRL ID|

> Example responses

> 200 Response

```json
{
  "certs": [
    {
      "cert_id": "C1",
      "cert_name": "cert1",
      "description": "string",
      "content": "string",
      "cert_type": [
        "string"
      ],
      "is_default": true,
      "version": 1,
      "create_time": 1700000000,
      "update_time": 1700000000,
      "valid_code": 0,
      "cert_revoked_date": 1700000000,
      "cert_revoked_reason": "string"
    }
  ],
  "crls": [
    {
      "crl_id": "L1",
      "crl_name": "crl1",
      "crl_content": "string"
    }
  ],
  "total_count": 0
}
```

<h3 id="getcertdefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Certificate detail|[CertListResponse](#schemacertlistresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteCertDefault

<a id="opIddeleteCertDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/cert/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/cert/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/cert/{id}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/cert/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/cert/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/cert/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/cert/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/cert/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/cert/{id}`

*Delete a single certificate (default provider)*

<h3 id="deletecertdefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|id|path|string|true|Certificate or CRL ID|

> Example responses

> 401 Response

```json
{
  "error": "string"
}
```

<h3 id="deletecertdefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Certificate deleted|None|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## listAttestationPoliciesDefault

<a id="opIdlistAttestationPoliciesDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/policy \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/policy HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/policy',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/policy',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/policy', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/policy");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/policy`

*List attestation policies (default provider)*

<h3 id="listattestationpoliciesdefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|ids|query|string|false|Comma-separated policy IDs|
|attester_type|query|string|false|Filter by attester type|
|limit|query|integer(int64)|false|Page size (1-10, default 10)|
|offset|query|integer(int64)|false|Offset (0-100000, default 0)|

> Example responses

> 200 Response

```json
{
  "policies": [
    {
      "id": "P1",
      "name": "policy1",
      "description": "string",
      "content": "string",
      "attester_type": "[\"tpm\",\"sgx\"]",
      "is_default": true,
      "version": 1,
      "update_time": 1700000000,
      "valid_code": 0
    }
  ],
  "total_count": 0
}
```

<h3 id="listattestationpoliciesdefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Policy list|[AttestationPolicyListResponse](#schemaattestationpolicylistresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## updateAttestationPolicyDefault

<a id="opIdupdateAttestationPolicyDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X PUT http://localhost:6666/rbs/v0/attestation/policy \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
PUT http://localhost:6666/rbs/v0/attestation/policy HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "id": "P1",
  "name": "string",
  "description": "string",
  "attester_type": [
    "string"
  ],
  "content_type": "string",
  "content": "string",
  "is_default": true
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/policy',
{
  method: 'PUT',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.put 'http://localhost:6666/rbs/v0/attestation/policy',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.put('http://localhost:6666/rbs/v0/attestation/policy', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('PUT','http://localhost:6666/rbs/v0/attestation/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/policy");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("PUT");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("PUT", "http://localhost:6666/rbs/v0/attestation/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`PUT /rbs/v0/attestation/policy`

*Update an attestation policy (default provider)*

> Body parameter

```json
{
  "id": "P1",
  "name": "string",
  "description": "string",
  "attester_type": [
    "string"
  ],
  "content_type": "string",
  "content": "string",
  "is_default": true
}
```

<h3 id="updateattestationpolicydefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[PolicyUpdateRequest](#schemapolicyupdaterequest)|true|none|

> Example responses

> 200 Response

```json
{
  "policy": {
    "id": "P1",
    "name": "policy1",
    "version": 2
  }
}
```

<h3 id="updateattestationpolicydefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Policy updated|[PolicyMutationResponse](#schemapolicymutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## createAttestationPolicyDefault

<a id="opIdcreateAttestationPolicyDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/attestation/policy \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
POST http://localhost:6666/rbs/v0/attestation/policy HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "name": "policy1",
  "attester_type": "[\"tpm\"]",
  "content_type": "jwt",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "is_default": true,
  "description": "string"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/policy',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/attestation/policy',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.post('http://localhost:6666/rbs/v0/attestation/policy', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/attestation/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/policy");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/attestation/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/attestation/policy`

*Create an attestation policy (default provider)*

> Body parameter

```json
{
  "name": "policy1",
  "attester_type": "[\"tpm\"]",
  "content_type": "jwt",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "is_default": true,
  "description": "string"
}
```

<h3 id="createattestationpolicydefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[PolicyCreateRequest](#schemapolicycreaterequest)|true|none|

> Example responses

> 201 Response

```json
{
  "policy": {
    "id": "P1",
    "name": "policy1",
    "version": 2
  }
}
```

<h3 id="createattestationpolicydefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Policy created|[PolicyMutationResponse](#schemapolicymutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteAttestationPoliciesDefault

<a id="opIddeleteAttestationPoliciesDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/policy \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/policy HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/policy',
{
  method: 'DELETE',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/policy',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/policy', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/policy");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/policy`

*Batch delete attestation policies (default provider)*

> Body parameter

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}
```

<h3 id="deleteattestationpoliciesdefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[PolicyDeleteRequest](#schemapolicydeleterequest)|true|none|

> Example responses

> 400 Response

```json
{
  "error": "string"
}
```

<h3 id="deleteattestationpoliciesdefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Policies deleted|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## getAttestationPolicyDefault

<a id="opIdgetAttestationPolicyDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/policy/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/policy/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/policy/{id}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/policy/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/policy/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/policy/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/policy/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/policy/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/policy/{id}`

*Get a single attestation policy (default provider)*

<h3 id="getattestationpolicydefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|id|path|string|true|Policy ID|

> Example responses

> 200 Response

```json
{
  "policies": [
    {
      "id": "P1",
      "name": "policy1",
      "description": "string",
      "content": "string",
      "attester_type": "[\"tpm\",\"sgx\"]",
      "is_default": true,
      "version": 1,
      "update_time": 1700000000,
      "valid_code": 0
    }
  ],
  "total_count": 0
}
```

<h3 id="getattestationpolicydefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Policy detail|[AttestationPolicyListResponse](#schemaattestationpolicylistresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteAttestationPolicyDefault

<a id="opIddeleteAttestationPolicyDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/policy/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/policy/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/policy/{id}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/policy/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/policy/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/policy/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/policy/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/policy/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/policy/{id}`

*Delete a single attestation policy (default provider)*

<h3 id="deleteattestationpolicydefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|id|path|string|true|Policy ID|

> Example responses

> 401 Response

```json
{
  "error": "string"
}
```

<h3 id="deleteattestationpolicydefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Policy deleted|None|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## listRefValuesDefault

<a id="opIdlistRefValuesDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/ref_value \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/ref_value HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/ref_value',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/ref_value',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/ref_value', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/ref_value', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/ref_value");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/ref_value", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/ref_value`

*List reference value baselines (default provider)*

<h3 id="listrefvaluesdefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|ids|query|string|false|Comma-separated ref_value IDs (1-10)|
|attester_type|query|string|false|Filter by attester type|
|limit|query|integer(int64)|false|Page size (1-10, default 10)|
|offset|query|integer(int64)|false|Offset (0-100000, default 0)|

> Example responses

> 200 Response

```json
{
  "ref_values": [
    {
      "id": "rv-001",
      "uid": "test_01",
      "name": "tpm-baseline",
      "attester_type": "tpm",
      "description": "TPM reference baseline",
      "content": "eyJhbGciOiJSUzI1NiJ9...",
      "content_type": "jwt",
      "version": 1,
      "valid_code": 0
    }
  ],
  "total_count": 0
}
```

<h3 id="listrefvaluesdefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Ref_value list|[RefValueListResponse](#schemarefvaluelistresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## updateRefValueDefault

<a id="opIdupdateRefValueDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X PUT http://localhost:6666/rbs/v0/attestation/ref_value \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
PUT http://localhost:6666/rbs/v0/attestation/ref_value HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "id": "rv-001",
  "name": "updated-baseline",
  "description": "string",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "base64"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/ref_value',
{
  method: 'PUT',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.put 'http://localhost:6666/rbs/v0/attestation/ref_value',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.put('http://localhost:6666/rbs/v0/attestation/ref_value', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('PUT','http://localhost:6666/rbs/v0/attestation/ref_value', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/ref_value");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("PUT");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("PUT", "http://localhost:6666/rbs/v0/attestation/ref_value", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`PUT /rbs/v0/attestation/ref_value`

*Update a reference value baseline (default provider)*

> Body parameter

```json
{
  "id": "rv-001",
  "name": "updated-baseline",
  "description": "string",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "base64"
}
```

<h3 id="updaterefvaluedefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[RefValueUpdateRequest](#schemarefvalueupdaterequest)|true|none|

> Example responses

> 200 Response

```json
{
  "ref_value": {
    "id": "rv-001",
    "name": "tpm-baseline",
    "version": 2
  }
}
```

<h3 id="updaterefvaluedefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Ref_value updated|[RefValueMutationResponse](#schemarefvaluemutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## createRefValueDefault

<a id="opIdcreateRefValueDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/attestation/ref_value \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
POST http://localhost:6666/rbs/v0/attestation/ref_value HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "name": "tpm-baseline",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "jwt",
  "description": "TPM reference baseline"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/ref_value',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/attestation/ref_value',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.post('http://localhost:6666/rbs/v0/attestation/ref_value', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/attestation/ref_value', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/ref_value");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/attestation/ref_value", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/attestation/ref_value`

*Create a reference value baseline (default provider)*

> Body parameter

```json
{
  "name": "tpm-baseline",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "jwt",
  "description": "TPM reference baseline"
}
```

<h3 id="createrefvaluedefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[RefValueCreateRequest](#schemarefvaluecreaterequest)|true|none|

> Example responses

> 201 Response

```json
{
  "ref_value": {
    "id": "rv-001",
    "name": "tpm-baseline",
    "version": 2
  }
}
```

<h3 id="createrefvaluedefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Ref_value created|[RefValueMutationResponse](#schemarefvaluemutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteRefValuesDefault

<a id="opIddeleteRefValuesDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/ref_value \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/ref_value HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/ref_value',
{
  method: 'DELETE',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/ref_value',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/ref_value', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/ref_value', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/ref_value");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/ref_value", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/ref_value`

*Batch delete reference value baselines (default provider)*

> Body parameter

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}
```

<h3 id="deleterefvaluesdefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[RefValueDeleteRequest](#schemarefvaluedeleterequest)|true|none|

> Example responses

> 400 Response

```json
{
  "error": "string"
}
```

<h3 id="deleterefvaluesdefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Ref_values deleted|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## getRefValueDefault

<a id="opIdgetRefValueDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/ref_value/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/ref_value/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/ref_value/{id}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/ref_value/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/ref_value/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/ref_value/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/ref_value/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/ref_value/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/ref_value/{id}`

*Get a single reference value baseline (default provider)*

<h3 id="getrefvaluedefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|id|path|string|true|Ref_value ID|

> Example responses

> 200 Response

```json
{
  "ref_values": [
    {
      "id": "rv-001",
      "uid": "test_01",
      "name": "tpm-baseline",
      "attester_type": "tpm",
      "description": "TPM reference baseline",
      "content": "eyJhbGciOiJSUzI1NiJ9...",
      "content_type": "jwt",
      "version": 1,
      "valid_code": 0
    }
  ],
  "total_count": 0
}
```

<h3 id="getrefvaluedefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Ref_value detail|[RefValueListResponse](#schemarefvaluelistresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteRefValueDefault

<a id="opIddeleteRefValueDefault"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/ref_value/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/ref_value/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/ref_value/{id}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/ref_value/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/ref_value/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/ref_value/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/ref_value/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/ref_value/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/ref_value/{id}`

*Delete a single reference value baseline (default provider)*

<h3 id="deleterefvaluedefault-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|id|path|string|true|Ref_value ID|

> Example responses

> 401 Response

```json
{
  "error": "string"
}
```

<h3 id="deleterefvaluedefault-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Ref_value deleted|None|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## listCerts

<a id="opIdlistCerts"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/{as_provider}/cert \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/{as_provider}/cert HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/{as_provider}/cert',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/{as_provider}/cert', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/cert");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/{as_provider}/cert", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/{as_provider}/cert`

*List certificates*

<h3 id="listcerts-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|ids|query|string|false|Comma-separated certificate IDs|
|cert_type|query|string|false|Filter by certificate type|
|limit|query|integer(int64)|false|Page size (1-10, default 10)|
|offset|query|integer(int64)|false|Offset (0-100000, default 0)|

> Example responses

> 200 Response

```json
{
  "certs": [
    {
      "cert_id": "C1",
      "cert_name": "cert1",
      "description": "string",
      "content": "string",
      "cert_type": [
        "string"
      ],
      "is_default": true,
      "version": 1,
      "create_time": 1700000000,
      "update_time": 1700000000,
      "valid_code": 0,
      "cert_revoked_date": 1700000000,
      "cert_revoked_reason": "string"
    }
  ],
  "crls": [
    {
      "crl_id": "L1",
      "crl_name": "crl1",
      "crl_content": "string"
    }
  ],
  "total_count": 0
}
```

<h3 id="listcerts-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Certificate list|[CertListResponse](#schemacertlistresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## updateCert

<a id="opIdupdateCert"></a>

> Code samples

```shell
# You can also use wget
curl -X PUT http://localhost:6666/rbs/v0/attestation/{as_provider}/cert \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
PUT http://localhost:6666/rbs/v0/attestation/{as_provider}/cert HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "id": "C1",
  "name": "string",
  "description": "string",
  "type": [
    "string"
  ],
  "content": "string",
  "is_default": true
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert',
{
  method: 'PUT',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.put 'http://localhost:6666/rbs/v0/attestation/{as_provider}/cert',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.put('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('PUT','http://localhost:6666/rbs/v0/attestation/{as_provider}/cert', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/cert");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("PUT");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("PUT", "http://localhost:6666/rbs/v0/attestation/{as_provider}/cert", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`PUT /rbs/v0/attestation/{as_provider}/cert`

*Update a certificate*

> Body parameter

```json
{
  "id": "C1",
  "name": "string",
  "description": "string",
  "type": [
    "string"
  ],
  "content": "string",
  "is_default": true
}
```

<h3 id="updatecert-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|body|body|[CertUpdateRequest](#schemacertupdaterequest)|true|none|

> Example responses

> 200 Response

```json
{
  "cert": {},
  "crl": {}
}
```

<h3 id="updatecert-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Certificate updated|[CertMutationResponse](#schemacertmutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## createCert

<a id="opIdcreateCert"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/attestation/{as_provider}/cert \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
POST http://localhost:6666/rbs/v0/attestation/{as_provider}/cert HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "name": "cert1",
  "type": "[\"tpm\"]",
  "description": "string",
  "content": "string",
  "crl_content": "string",
  "is_default": true
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/attestation/{as_provider}/cert',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.post('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/attestation/{as_provider}/cert', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/cert");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/attestation/{as_provider}/cert", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/attestation/{as_provider}/cert`

*Create a certificate*

> Body parameter

```json
{
  "name": "cert1",
  "type": "[\"tpm\"]",
  "description": "string",
  "content": "string",
  "crl_content": "string",
  "is_default": true
}
```

<h3 id="createcert-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|body|body|[CertCreateRequest](#schemacertcreaterequest)|true|none|

> Example responses

> 201 Response

```json
{
  "cert": {},
  "crl": {}
}
```

<h3 id="createcert-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Certificate created|[CertMutationResponse](#schemacertmutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteCerts

<a id="opIddeleteCerts"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/cert \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/cert HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "type": "refvalue"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert',
{
  method: 'DELETE',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/{as_provider}/cert',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/{as_provider}/cert', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/cert");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/{as_provider}/cert", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/{as_provider}/cert`

*Batch delete certificates*

> Body parameter

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "type": "refvalue"
}
```

<h3 id="deletecerts-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|body|body|[CertDeleteRequest](#schemacertdeleterequest)|true|none|

> Example responses

> 400 Response

```json
{
  "error": "string"
}
```

<h3 id="deletecerts-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Certificates deleted|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## getCert

<a id="opIdgetCert"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/{as_provider}/cert/{id}`

*Get a single certificate*

<h3 id="getcert-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|id|path|string|true|Certificate or CRL ID|

> Example responses

> 200 Response

```json
{
  "certs": [
    {
      "cert_id": "C1",
      "cert_name": "cert1",
      "description": "string",
      "content": "string",
      "cert_type": [
        "string"
      ],
      "is_default": true,
      "version": 1,
      "create_time": 1700000000,
      "update_time": 1700000000,
      "valid_code": 0,
      "cert_revoked_date": 1700000000,
      "cert_revoked_reason": "string"
    }
  ],
  "crls": [
    {
      "crl_id": "L1",
      "crl_name": "crl1",
      "crl_content": "string"
    }
  ],
  "total_count": 0
}
```

<h3 id="getcert-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Certificate detail|[CertListResponse](#schemacertlistresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteCert

<a id="opIddeleteCert"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/{as_provider}/cert/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/{as_provider}/cert/{id}`

*Delete a single certificate*

<h3 id="deletecert-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|id|path|string|true|Certificate or CRL ID|

> Example responses

> 401 Response

```json
{
  "error": "string"
}
```

<h3 id="deletecert-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Certificate deleted|None|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## listAttestationPolicies

<a id="opIdlistAttestationPolicies"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/{as_provider}/policy \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/{as_provider}/policy HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/{as_provider}/policy',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/{as_provider}/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/policy");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/{as_provider}/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/{as_provider}/policy`

*List attestation policies*

<h3 id="listattestationpolicies-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|ids|query|string|false|Comma-separated policy IDs|
|attester_type|query|string|false|Filter by attester type|
|limit|query|integer(int64)|false|Page size (1-10, default 10)|
|offset|query|integer(int64)|false|Offset (0-100000, default 0)|

> Example responses

> 200 Response

```json
{
  "policies": [
    {
      "id": "P1",
      "name": "policy1",
      "description": "string",
      "content": "string",
      "attester_type": "[\"tpm\",\"sgx\"]",
      "is_default": true,
      "version": 1,
      "update_time": 1700000000,
      "valid_code": 0
    }
  ],
  "total_count": 0
}
```

<h3 id="listattestationpolicies-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Policy list|[AttestationPolicyListResponse](#schemaattestationpolicylistresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## updateAttestationPolicy

<a id="opIdupdateAttestationPolicy"></a>

> Code samples

```shell
# You can also use wget
curl -X PUT http://localhost:6666/rbs/v0/attestation/{as_provider}/policy \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
PUT http://localhost:6666/rbs/v0/attestation/{as_provider}/policy HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "id": "P1",
  "name": "string",
  "description": "string",
  "attester_type": [
    "string"
  ],
  "content_type": "string",
  "content": "string",
  "is_default": true
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy',
{
  method: 'PUT',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.put 'http://localhost:6666/rbs/v0/attestation/{as_provider}/policy',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.put('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('PUT','http://localhost:6666/rbs/v0/attestation/{as_provider}/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/policy");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("PUT");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("PUT", "http://localhost:6666/rbs/v0/attestation/{as_provider}/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`PUT /rbs/v0/attestation/{as_provider}/policy`

*Update an attestation policy*

> Body parameter

```json
{
  "id": "P1",
  "name": "string",
  "description": "string",
  "attester_type": [
    "string"
  ],
  "content_type": "string",
  "content": "string",
  "is_default": true
}
```

<h3 id="updateattestationpolicy-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|body|body|[PolicyUpdateRequest](#schemapolicyupdaterequest)|true|none|

> Example responses

> 200 Response

```json
{
  "policy": {
    "id": "P1",
    "name": "policy1",
    "version": 2
  }
}
```

<h3 id="updateattestationpolicy-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Policy updated|[PolicyMutationResponse](#schemapolicymutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## createAttestationPolicy

<a id="opIdcreateAttestationPolicy"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/attestation/{as_provider}/policy \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
POST http://localhost:6666/rbs/v0/attestation/{as_provider}/policy HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "name": "policy1",
  "attester_type": "[\"tpm\"]",
  "content_type": "jwt",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "is_default": true,
  "description": "string"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/attestation/{as_provider}/policy',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.post('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/attestation/{as_provider}/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/policy");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/attestation/{as_provider}/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/attestation/{as_provider}/policy`

*Create an attestation policy*

> Body parameter

```json
{
  "name": "policy1",
  "attester_type": "[\"tpm\"]",
  "content_type": "jwt",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "is_default": true,
  "description": "string"
}
```

<h3 id="createattestationpolicy-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|body|body|[PolicyCreateRequest](#schemapolicycreaterequest)|true|none|

> Example responses

> 201 Response

```json
{
  "policy": {
    "id": "P1",
    "name": "policy1",
    "version": 2
  }
}
```

<h3 id="createattestationpolicy-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Policy created|[PolicyMutationResponse](#schemapolicymutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteAttestationPolicies

<a id="opIddeleteAttestationPolicies"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/policy \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/policy HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy',
{
  method: 'DELETE',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/{as_provider}/policy',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/{as_provider}/policy', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/policy");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/{as_provider}/policy", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/{as_provider}/policy`

*Batch delete attestation policies*

> Body parameter

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}
```

<h3 id="deleteattestationpolicies-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|body|body|[PolicyDeleteRequest](#schemapolicydeleterequest)|true|none|

> Example responses

> 400 Response

```json
{
  "error": "string"
}
```

<h3 id="deleteattestationpolicies-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Policies deleted|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## getAttestationPolicy

<a id="opIdgetAttestationPolicy"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/{as_provider}/policy/{id}`

*Get a single attestation policy*

<h3 id="getattestationpolicy-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|id|path|string|true|Policy ID|

> Example responses

> 200 Response

```json
{
  "policies": [
    {
      "id": "P1",
      "name": "policy1",
      "description": "string",
      "content": "string",
      "attester_type": "[\"tpm\",\"sgx\"]",
      "is_default": true,
      "version": 1,
      "update_time": 1700000000,
      "valid_code": 0
    }
  ],
  "total_count": 0
}
```

<h3 id="getattestationpolicy-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Policy detail|[AttestationPolicyListResponse](#schemaattestationpolicylistresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteAttestationPolicy

<a id="opIddeleteAttestationPolicy"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/{as_provider}/policy/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/{as_provider}/policy/{id}`

*Delete a single attestation policy*

<h3 id="deleteattestationpolicy-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|id|path|string|true|Policy ID|

> Example responses

> 401 Response

```json
{
  "error": "string"
}
```

<h3 id="deleteattestationpolicy-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Policy deleted|None|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## listRefValues

<a id="opIdlistRefValues"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/{as_provider}/ref_value`

*List reference value baselines*

<h3 id="listrefvalues-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|ids|query|string|false|Comma-separated ref_value IDs (1-10)|
|attester_type|query|string|false|Filter by attester type|
|limit|query|integer(int64)|false|Page size (1-10, default 10)|
|offset|query|integer(int64)|false|Offset (0-100000, default 0)|

> Example responses

> 200 Response

```json
{
  "ref_values": [
    {
      "id": "rv-001",
      "uid": "test_01",
      "name": "tpm-baseline",
      "attester_type": "tpm",
      "description": "TPM reference baseline",
      "content": "eyJhbGciOiJSUzI1NiJ9...",
      "content_type": "jwt",
      "version": 1,
      "valid_code": 0
    }
  ],
  "total_count": 0
}
```

<h3 id="listrefvalues-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Ref_value list|[RefValueListResponse](#schemarefvaluelistresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## updateRefValue

<a id="opIdupdateRefValue"></a>

> Code samples

```shell
# You can also use wget
curl -X PUT http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
PUT http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "id": "rv-001",
  "name": "updated-baseline",
  "description": "string",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "base64"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value',
{
  method: 'PUT',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.put 'http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.put('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('PUT','http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("PUT");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("PUT", "http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`PUT /rbs/v0/attestation/{as_provider}/ref_value`

*Update a reference value baseline*

> Body parameter

```json
{
  "id": "rv-001",
  "name": "updated-baseline",
  "description": "string",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "base64"
}
```

<h3 id="updaterefvalue-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|body|body|[RefValueUpdateRequest](#schemarefvalueupdaterequest)|true|none|

> Example responses

> 200 Response

```json
{
  "ref_value": {
    "id": "rv-001",
    "name": "tpm-baseline",
    "version": 2
  }
}
```

<h3 id="updaterefvalue-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Ref_value updated|[RefValueMutationResponse](#schemarefvaluemutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## createRefValue

<a id="opIdcreateRefValue"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
POST http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "name": "tpm-baseline",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "jwt",
  "description": "TPM reference baseline"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.post 'http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.post('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /rbs/v0/attestation/{as_provider}/ref_value`

*Create a reference value baseline*

> Body parameter

```json
{
  "name": "tpm-baseline",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "jwt",
  "description": "TPM reference baseline"
}
```

<h3 id="createrefvalue-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|body|body|[RefValueCreateRequest](#schemarefvaluecreaterequest)|true|none|

> Example responses

> 201 Response

```json
{
  "ref_value": {
    "id": "rv-001",
    "name": "tpm-baseline",
    "version": 2
  }
}
```

<h3 id="createrefvalue-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Ref_value created|[RefValueMutationResponse](#schemarefvaluemutationresponse)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Provider not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteRefValues

<a id="opIddeleteRefValues"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value HTTP/1.1
Host: localhost:6666
Content-Type: application/json
Accept: application/json

```

```javascript
const inputBody = '{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value',
{
  method: 'DELETE',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Content-Type' => 'application/json',
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/{as_provider}/ref_value`

*Batch delete reference value baselines*

> Body parameter

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}
```

<h3 id="deleterefvalues-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|body|body|[RefValueDeleteRequest](#schemarefvaluedeleterequest)|true|none|

> Example responses

> 400 Response

```json
{
  "error": "string"
}
```

<h3 id="deleterefvalues-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Ref_values deleted|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad request|[ErrorBody](#schemaerrorbody)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## getRefValue

<a id="opIdgetRefValue"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
GET http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.get('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/attestation/{as_provider}/ref_value/{id}`

*Get a single reference value baseline*

<h3 id="getrefvalue-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|id|path|string|true|Ref_value ID|

> Example responses

> 200 Response

```json
{
  "ref_values": [
    {
      "id": "rv-001",
      "uid": "test_01",
      "name": "tpm-baseline",
      "attester_type": "tpm",
      "description": "TPM reference baseline",
      "content": "eyJhbGciOiJSUzI1NiJ9...",
      "content_type": "jwt",
      "version": 1,
      "valid_code": 0
    }
  ],
  "total_count": 0
}
```

<h3 id="getrefvalue-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Ref_value detail|[RefValueListResponse](#schemarefvaluelistresponse)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## deleteRefValue

<a id="opIddeleteRefValue"></a>

> Code samples

```shell
# You can also use wget
curl -X DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id} \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer {access-token}'

```

```http
DELETE http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id} HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json',
  'Authorization':'Bearer {access-token}'
};

fetch('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'Authorization' => 'Bearer {access-token}'
}

result = RestClient.delete 'http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer {access-token}'
}

r = requests.delete('http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'Authorization' => 'Bearer {access-token}',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('DELETE','http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("DELETE");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
        "Authorization": []string{"Bearer {access-token}"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "http://localhost:6666/rbs/v0/attestation/{as_provider}/ref_value/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`DELETE /rbs/v0/attestation/{as_provider}/ref_value/{id}`

*Delete a single reference value baseline*

<h3 id="deleterefvalue-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|path|string|true|Attestation provider name|
|id|path|string|true|Ref_value ID|

> Example responses

> 401 Response

```json
{
  "error": "string"
}
```

<h3 id="deleterefvalue-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Ref_value deleted|None|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Unauthorized|[ErrorBody](#schemaerrorbody)|
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not found|[ErrorBody](#schemaerrorbody)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|GTA unreachable or timeout; other GTA statuses forwarded as-is|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
bearerAuth
</aside>

## getAuthChallenge

<a id="opIdgetAuthChallenge"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:6666/rbs/v0/challenge \
  -H 'Accept: application/json'

```

```http
GET http://localhost:6666/rbs/v0/challenge HTTP/1.1
Host: localhost:6666
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json'
};

fetch('http://localhost:6666/rbs/v0/challenge',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json'
}

result = RestClient.get 'http://localhost:6666/rbs/v0/challenge',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json'
}

r = requests.get('http://localhost:6666/rbs/v0/challenge', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:6666/rbs/v0/challenge', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:6666/rbs/v0/challenge");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:6666/rbs/v0/challenge", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /rbs/v0/challenge`

*Obtain an attestation challenge (nonce)*

<h3 id="getauthchallenge-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|as_provider|query|string|false|Target provider ID for challenge|

> Example responses

> 200 Response

```json
{
  "nonce": "string"
}
```

<h3 id="getauthchallenge-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Challenge payload with nonce (JSON).|[AuthChallengeResponse](#schemaauthchallengeresponse)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal server error.|[ErrorBody](#schemaerrorbody)|
|502|[Bad Gateway](https://tools.ietf.org/html/rfc7231#section-6.6.3)|Attestation backend returned a non-2xx; RBS forwards GTA's status code and wraps GTA's body in the error field.|[ErrorBody](#schemaerrorbody)|
|503|[Service Unavailable](https://tools.ietf.org/html/rfc7231#section-6.6.4)|Attestation provider unreachable or timed out.|[ErrorBody](#schemaerrorbody)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None
</aside>

# Schemas

<h2 id="tocS_AttestRequest">AttestRequest</h2>
<!-- backwards compatibility -->
<a id="schemaattestrequest"></a>
<a id="schema_AttestRequest"></a>
<a id="tocSattestrequest"></a>
<a id="tocsattestrequest"></a>

```json
{
  "as_provider": "string",
  "rbc_evidences": {
    "agent_version": "string",
    "measurements": [
      {
        "nonce": "string",
        "node_id": "string",
        "nonce_type": "string",
        "token_fmt": "string",
        "attester_data": {},
        "evidences": [
          {
            "attester_type": "string",
            "evidence": null,
            "policy_ids": [
              "string"
            ],
            "ref_value_id": "string"
          }
        ]
      }
    ]
  }
}

```

Request body for POST /rbs/v0/attest.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|as_provider|string,null|false|none|Optional attestation backend id (e.g. gta); default is deployment-specific.|
|rbc_evidences|[RbcEvidencesPayload](#schemarbcevidencespayload)|false|none|Evidence bundle from RBC.|

<h2 id="tocS_AttestResponse">AttestResponse</h2>
<!-- backwards compatibility -->
<a id="schemaattestresponse"></a>
<a id="schema_AttestResponse"></a>
<a id="tocSattestresponse"></a>
<a id="tocsattestresponse"></a>

```json
{
  "token": "string"
}

```

Response for POST /rbs/v0/attest.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|token|string|true|none|AttestToken or session JWT for subsequent Bearer resource access.|

<h2 id="tocS_AttestationDeleteType">AttestationDeleteType</h2>
<!-- backwards compatibility -->
<a id="schemaattestationdeletetype"></a>
<a id="schema_AttestationDeleteType"></a>
<a id="tocSattestationdeletetype"></a>
<a id="tocsattestationdeletetype"></a>

```json
"id"

```

Delete mode for ref_value/cert DELETE operations.

GTA accepts `"id"`, `"all"`, `"type"` for ref_value and cert.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|Delete mode for ref_value/cert DELETE operations.<br><br>GTA accepts `"id"`, `"all"`, `"type"` for ref_value and cert.|

#### Enumerated Values

|Property|Value|
|---|---|
|*anonymous*|id|
|*anonymous*|all|
|*anonymous*|type|

<h2 id="tocS_AttestationPolicy">AttestationPolicy</h2>
<!-- backwards compatibility -->
<a id="schemaattestationpolicy"></a>
<a id="schema_AttestationPolicy"></a>
<a id="tocSattestationpolicy"></a>
<a id="tocsattestationpolicy"></a>

```json
{
  "id": "P1",
  "name": "policy1",
  "description": "string",
  "content": "string",
  "attester_type": "[\"tpm\",\"sgx\"]",
  "is_default": true,
  "version": 1,
  "update_time": 1700000000,
  "valid_code": 0
}

```

Attestation policy entity returned by GTA.

Named `AttestationPolicy` to distinguish from RBS local resource policy
(`Policy`/`PolicyResponse` in `t_res_policy`). `id`/`name`/`attester_type`
are always present in both GTA by_type/all (summary) and by_ids (full)
responses, so they are mandatory. Other fields appear only in by_ids.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|Stable policy identifier.|
|name|string|true|none|Policy name.|
|description|string,null|false|none|Optional description (by_ids path only).|
|content|string,null|false|none|Policy content (JWT or text) (by_ids path only).|
|attester_type|[string]|true|none|Attester type list (array, unlike ref_value's scalar attester_type).|
|is_default|boolean,null|false|none|Whether this is the default policy (by_ids path only).|
|version|integer,null(int32)|false|none|Policy version (by_ids path only).|
|update_time|integer,null(int64)|false|none|Last update timestamp (Unix epoch seconds).|
|valid_code|integer,null(int32)|false|none|Validity code: 0 = valid, 1 = invalid (by_ids path only).|

<h2 id="tocS_AttestationPolicyListResponse">AttestationPolicyListResponse</h2>
<!-- backwards compatibility -->
<a id="schemaattestationpolicylistresponse"></a>
<a id="schema_AttestationPolicyListResponse"></a>
<a id="tocSattestationpolicylistresponse"></a>
<a id="tocsattestationpolicylistresponse"></a>

```json
{
  "policies": [
    {
      "id": "P1",
      "name": "policy1",
      "description": "string",
      "content": "string",
      "attester_type": "[\"tpm\",\"sgx\"]",
      "is_default": true,
      "version": 1,
      "update_time": 1700000000,
      "valid_code": 0
    }
  ],
  "total_count": 0
}

```

Paginated response for GET attestation policy list.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|policies|[[AttestationPolicy](#schemaattestationpolicy)]|true|none|List of policies matching the query.|
|total_count|integer,null(int64)|false|none|Total matching count.|

<h2 id="tocS_AttesterData">AttesterData</h2>
<!-- backwards compatibility -->
<a id="schemaattesterdata"></a>
<a id="schema_AttesterData"></a>
<a id="tocSattesterdata"></a>
<a id="tocsattesterdata"></a>

```json
{
  "runtime_data": {
    "property1": null,
    "property2": null
  }
}

```

Optional attester-supplied metadata, carried per measurement under
`rbc_evidences.measurements[].attester_data`.

`runtime_data` must not duplicate the challenge nonce (nonce lives only under
`rbc_evidences.measurements[].nonce`).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|runtime_data|object,null|false|none|Key/value runtime fields (e.g. attester_pubkey as JWK for encrypted resource return);<br>excludes nonce.|
|» **additionalProperties**|any|false|none|none|

<h2 id="tocS_AuthChallengeResponse">AuthChallengeResponse</h2>
<!-- backwards compatibility -->
<a id="schemaauthchallengeresponse"></a>
<a id="schema_AuthChallengeResponse"></a>
<a id="tocSauthchallengeresponse"></a>
<a id="tocsauthchallengeresponse"></a>

```json
{
  "nonce": "string"
}

```

Response for GET /rbs/v0/challenge (attestation challenge).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|nonce|string|true|none|Challenge value for binding attestation (opaque; often Base64).<br>Use the field value as-is in `rbc_evidences.measurements[].nonce`<br>for POST /rbs/v0/attest and POST .../retrieve.|

<h2 id="tocS_AuthType">AuthType</h2>
<!-- backwards compatibility -->
<a id="schemaauthtype"></a>
<a id="schema_AuthType"></a>
<a id="tocSauthtype"></a>
<a id="tocsauthtype"></a>

```json
"jwt"

```

Authentication type. Add new types here.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|Authentication type. Add new types here.|

#### Enumerated Values

|Property|Value|
|---|---|
|*anonymous*|jwt|

<h2 id="tocS_BuildMetadata">BuildMetadata</h2>
<!-- backwards compatibility -->
<a id="schemabuildmetadata"></a>
<a id="schema_BuildMetadata"></a>
<a id="tocSbuildmetadata"></a>
<a id="tocsbuildmetadata"></a>

```json
{
  "version": "0.1.0",
  "git_hash": "",
  "build_date": ""
}

```

Build-time identity for the running binary.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|version|string|true|none|Cargo package / release version (semver).|
|git_hash|string|true|none|Git commit hash at build time (hex), or empty when not embedded at build.|
|build_date|string|true|none|Build timestamp (UTC), typically RFC 3339, or empty when not embedded at build.|

<h2 id="tocS_CertCreateRequest">CertCreateRequest</h2>
<!-- backwards compatibility -->
<a id="schemacertcreaterequest"></a>
<a id="schema_CertCreateRequest"></a>
<a id="tocScertcreaterequest"></a>
<a id="tocscertcreaterequest"></a>

```json
{
  "name": "cert1",
  "type": "[\"tpm\"]",
  "description": "string",
  "content": "string",
  "crl_content": "string",
  "is_default": true
}

```

Request body for POST cert (create).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|name|string|true|none|Certificate name (non-empty).|
|type|[string]|true|none|Certificate type list (JSON field name `type`).|
|description|string,null|false|none|Optional description.|
|content|string,null|false|none|Certificate content; required when `cert_type` does not contain `crl`.|
|crl_content|string,null|false|none|CRL content; required when `cert_type` contains `crl`.|
|is_default|boolean,null|false|none|Whether to set as default certificate.|

<h2 id="tocS_CertDeleteRequest">CertDeleteRequest</h2>
<!-- backwards compatibility -->
<a id="schemacertdeleterequest"></a>
<a id="schema_CertDeleteRequest"></a>
<a id="tocScertdeleterequest"></a>
<a id="tocscertdeleterequest"></a>

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "type": "refvalue"
}

```

Request body for DELETE cert (batch delete).

GTA accepts `delete_type` = `"id"`/`"all"`/`"type"`, with
`cert_type` (JSON field name `type`) as the type filter.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|delete_type|[AttestationDeleteType](#schemaattestationdeletetype)|true|none|Delete mode.|
|ids|array,null|false|none|IDs to delete (required when `delete_type` is `Id`).|
|type|string,null|false|none|Cert type filter (required when `delete_type` is `Type`; JSON field name `type`).|

<h2 id="tocS_CertListResponse">CertListResponse</h2>
<!-- backwards compatibility -->
<a id="schemacertlistresponse"></a>
<a id="schema_CertListResponse"></a>
<a id="tocScertlistresponse"></a>
<a id="tocscertlistresponse"></a>

```json
{
  "certs": [
    {
      "cert_id": "C1",
      "cert_name": "cert1",
      "description": "string",
      "content": "string",
      "cert_type": [
        "string"
      ],
      "is_default": true,
      "version": 1,
      "create_time": 1700000000,
      "update_time": 1700000000,
      "valid_code": 0,
      "cert_revoked_date": 1700000000,
      "cert_revoked_reason": "string"
    }
  ],
  "crls": [
    {
      "crl_id": "L1",
      "crl_name": "crl1",
      "crl_content": "string"
    }
  ],
  "total_count": 0
}

```

Paginated response for GET cert list.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|certs|[[CertRecord](#schemacertrecord)]|false|none|List of certificates matching the query.|
|crls|[[CrlRecord](#schemacrlrecord)]|false|none|List of CRL records matching the query.|
|total_count|integer,null(int64)|false|none|Total matching count.|

<h2 id="tocS_CertMutationResponse">CertMutationResponse</h2>
<!-- backwards compatibility -->
<a id="schemacertmutationresponse"></a>
<a id="schema_CertMutationResponse"></a>
<a id="tocScertmutationresponse"></a>
<a id="tocscertmutationresponse"></a>

```json
{
  "cert": {},
  "crl": {}
}

```

Response for POST/PUT cert (create/update mutation).

GTA wraps the result in a `cert` or `crl` key; only one is present.
RBS is a stateless proxy and passes the wrapper through unchanged.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|cert|any|false|none|none|

oneOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|null|false|none|none|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|[CertMutationResult](#schemacertmutationresult)|false|none|Present when a cert was created/updated.|

continued

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|crl|any|false|none|none|

oneOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|null|false|none|none|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|[CrlMutationResult](#schemacrlmutationresult)|false|none|Present when a CRL was created/updated.|

<h2 id="tocS_CertMutationResult">CertMutationResult</h2>
<!-- backwards compatibility -->
<a id="schemacertmutationresult"></a>
<a id="schema_CertMutationResult"></a>
<a id="tocScertmutationresult"></a>
<a id="tocscertmutationresult"></a>

```json
{
  "cert_id": "C1",
  "cert_name": "cert1",
  "version": 2
}

```

Inner mutation result for cert create/update.

GTA returns `{"cert": {"cert_id":"...", "cert_name":"...", "version": 1}}`.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|cert_id|string,null|false|none|Certificate ID.|
|cert_name|string,null|false|none|Certificate name.|
|version|integer,null(int32)|false|none|New version after mutation.|

<h2 id="tocS_CertRecord">CertRecord</h2>
<!-- backwards compatibility -->
<a id="schemacertrecord"></a>
<a id="schema_CertRecord"></a>
<a id="tocScertrecord"></a>
<a id="tocscertrecord"></a>

```json
{
  "cert_id": "C1",
  "cert_name": "cert1",
  "description": "string",
  "content": "string",
  "cert_type": [
    "string"
  ],
  "is_default": true,
  "version": 1,
  "create_time": 1700000000,
  "update_time": 1700000000,
  "valid_code": 0,
  "cert_revoked_date": 1700000000,
  "cert_revoked_reason": "string"
}

```

Certificate record returned by GTA.

All fields are optional: GTA's `CertRespInfo` serializes every field
with `skip_serializing_if = "Option::is_none"`, so the present subset
depends on the query path and the underlying database row.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|cert_id|string,null|false|none|Stable certificate identifier.|
|cert_name|string,null|false|none|Certificate name.|
|description|string,null|false|none|Optional description.|
|content|string,null|false|none|Certificate content (PEM etc.).|
|cert_type|array,null|false|none|Certificate type list.|
|is_default|boolean,null|false|none|Whether this is the default certificate.|
|version|integer,null(int32)|false|none|Certificate version.|
|create_time|integer,null(int64)|false|none|Creation timestamp (Unix epoch seconds).|
|update_time|integer,null(int64)|false|none|Last update timestamp (Unix epoch seconds).|
|valid_code|integer,null(int32)|false|none|Validity code.|
|cert_revoked_date|integer,null(int64)|false|none|Revocation date (Unix epoch seconds).|
|cert_revoked_reason|string,null|false|none|Revocation reason.|

<h2 id="tocS_CertUpdateRequest">CertUpdateRequest</h2>
<!-- backwards compatibility -->
<a id="schemacertupdaterequest"></a>
<a id="schema_CertUpdateRequest"></a>
<a id="tocScertupdaterequest"></a>
<a id="tocscertupdaterequest"></a>

```json
{
  "id": "C1",
  "name": "string",
  "description": "string",
  "type": [
    "string"
  ],
  "content": "string",
  "is_default": true
}

```

Request body for PUT cert (update).

`id` is required (collection-level operation, id in body not path).
GTA rejects `content` on update — the field is passed through so GTA
can return the appropriate error.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|ID of the certificate to update.|
|name|string,null|false|none|New name.|
|description|string,null|false|none|New description.|
|type|array,null|false|none|New certificate type list (JSON field name `type`). Must not contain `crl`.|
|content|string,null|false|none|Certificate content — GTA rejects this on update.|
|is_default|boolean,null|false|none|Whether to set as default certificate.|

<h2 id="tocS_ChallengeRequest">ChallengeRequest</h2>
<!-- backwards compatibility -->
<a id="schemachallengerequest"></a>
<a id="schema_ChallengeRequest"></a>
<a id="tocSchallengerequest"></a>
<a id="tocschallengerequest"></a>

```json
{
  "as_provider": "string"
}

```

Query parameter for GET /rbs/v0/challenge (challenge request).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|as_provider|string,null|false|none|Optional attestation backend id (e.g. gta); default is deployment-specific.|

<h2 id="tocS_CreatePolicyRequest">CreatePolicyRequest</h2>
<!-- backwards compatibility -->
<a id="schemacreatepolicyrequest"></a>
<a id="schema_CreatePolicyRequest"></a>
<a id="tocScreatepolicyrequest"></a>
<a id="tocscreatepolicyrequest"></a>

```json
{
  "name": "string",
  "content_type": "string",
  "content": "string"
}

```

Policy create request body.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|name|string|true|none|none|
|content_type|string|true|none|none|
|content|string|true|none|none|

<h2 id="tocS_CreateResourceRequest">CreateResourceRequest</h2>
<!-- backwards compatibility -->
<a id="schemacreateresourcerequest"></a>
<a id="schema_CreateResourceRequest"></a>
<a id="tocScreateresourcerequest"></a>
<a id="tocscreateresourcerequest"></a>

```json
{
  "policy_id": "string",
  "content_type": "string",
  "export_mode": "string",
  "additional_info": "string"
}

```

Request body for `POST /rbs/v0/{uri}` — create a resource.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|policy_id|string|true|none|none|
|content_type|string,null|false|none|none|
|export_mode|string,null|false|none|none|
|additional_info|string,null|false|none|none|

<h2 id="tocS_CrlMutationResult">CrlMutationResult</h2>
<!-- backwards compatibility -->
<a id="schemacrlmutationresult"></a>
<a id="schema_CrlMutationResult"></a>
<a id="tocScrlmutationresult"></a>
<a id="tocscrlmutationresult"></a>

```json
{
  "crl_id": "L1",
  "crl_name": "crl1"
}

```

Inner mutation result for CRL create.

GTA returns `{"crl": {"crl_id":"...", "crl_name":"..."}}`.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|crl_id|string,null|false|none|CRL ID.|
|crl_name|string,null|false|none|CRL name.|

<h2 id="tocS_CrlRecord">CrlRecord</h2>
<!-- backwards compatibility -->
<a id="schemacrlrecord"></a>
<a id="schema_CrlRecord"></a>
<a id="tocScrlrecord"></a>
<a id="tocscrlrecord"></a>

```json
{
  "crl_id": "L1",
  "crl_name": "crl1",
  "crl_content": "string"
}

```

CRL (Certificate Revocation List) record returned by GTA.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|crl_id|string,null|false|none|Stable CRL identifier.|
|crl_name|string,null|false|none|CRL name.|
|crl_content|string,null|false|none|CRL content.|

<h2 id="tocS_ErrorBody">ErrorBody</h2>
<!-- backwards compatibility -->
<a id="schemaerrorbody"></a>
<a id="schema_ErrorBody"></a>
<a id="tocSerrorbody"></a>
<a id="tocserrorbody"></a>

```json
{
  "error": "string"
}

```

Error payload for HTTP error responses (e.g. 500).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|error|string|true|none|Error string for the caller: may be a stable code, a short machine-oriented label,<br>or a concise human-readable message. Must not include stack traces or secrets.|

<h2 id="tocS_PolicyCreateRequest">PolicyCreateRequest</h2>
<!-- backwards compatibility -->
<a id="schemapolicycreaterequest"></a>
<a id="schema_PolicyCreateRequest"></a>
<a id="tocSpolicycreaterequest"></a>
<a id="tocspolicycreaterequest"></a>

```json
{
  "name": "policy1",
  "attester_type": "[\"tpm\"]",
  "content_type": "jwt",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "is_default": true,
  "description": "string"
}

```

Request body for POST attestation policy (create).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|name|string|true|none|Policy name (non-empty).|
|attester_type|[string]|true|none|Attester type list (non-empty array).|
|content_type|string|true|none|Content encoding (required): "jwt" or "text".|
|content|string|true|none|Policy content (non-empty).|
|is_default|boolean,null|false|none|Whether to set as default policy.|
|description|string,null|false|none|Optional description.|

<h2 id="tocS_PolicyDeleteRequest">PolicyDeleteRequest</h2>
<!-- backwards compatibility -->
<a id="schemapolicydeleterequest"></a>
<a id="schema_PolicyDeleteRequest"></a>
<a id="tocSpolicydeleterequest"></a>
<a id="tocspolicydeleterequest"></a>

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}

```

Request body for DELETE policy (batch delete).

GTA accepts `delete_type` = `"id"`/`"all"`/`"attester_type"`, with
`attester_type` as the type filter.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|delete_type|[PolicyDeleteType](#schemapolicydeletetype)|true|none|Delete mode.|
|ids|array,null|false|none|IDs to delete (required when `delete_type` is `Id`).|
|attester_type|string,null|false|none|Attester type filter (required when `delete_type` is `AttesterType`).|

<h2 id="tocS_PolicyDeleteType">PolicyDeleteType</h2>
<!-- backwards compatibility -->
<a id="schemapolicydeletetype"></a>
<a id="schema_PolicyDeleteType"></a>
<a id="tocSpolicydeletetype"></a>
<a id="tocspolicydeletetype"></a>

```json
"id"

```

Delete mode for policy DELETE operations.

GTA accepts `"id"`, `"all"`, `"attester_type"` for policy.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|Delete mode for policy DELETE operations.<br><br>GTA accepts `"id"`, `"all"`, `"attester_type"` for policy.|

#### Enumerated Values

|Property|Value|
|---|---|
|*anonymous*|id|
|*anonymous*|all|
|*anonymous*|attester_type|

<h2 id="tocS_PolicyListResponse">PolicyListResponse</h2>
<!-- backwards compatibility -->
<a id="schemapolicylistresponse"></a>
<a id="schema_PolicyListResponse"></a>
<a id="tocSpolicylistresponse"></a>
<a id="tocspolicylistresponse"></a>

```json
{
  "items": [
    {
      "policy_id": "string",
      "policy_name": "string",
      "policy_version": 0,
      "content_type": "string",
      "created_at": "string",
      "updated_at": "string",
      "applied_resources": [
        "string"
      ]
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}

```

Policy list response.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|items|[[PolicyResponse](#schemapolicyresponse)]|true|none|[Policy response returned to callers.]|
|total_count|integer(int64)|true|none|none|
|limit|integer(int64)|true|none|none|
|offset|integer(int64)|true|none|none|

<h2 id="tocS_PolicyMutation">PolicyMutation</h2>
<!-- backwards compatibility -->
<a id="schemapolicymutation"></a>
<a id="schema_PolicyMutation"></a>
<a id="tocSpolicymutation"></a>
<a id="tocspolicymutation"></a>

```json
{
  "id": "P1",
  "name": "policy1",
  "version": 2
}

```

Inner mutation result for policy create/update.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|ID of the mutated policy.|
|name|string|true|none|Name of the mutated policy.|
|version|integer(int32)|true|none|New version after mutation.|

<h2 id="tocS_PolicyMutationResponse">PolicyMutationResponse</h2>
<!-- backwards compatibility -->
<a id="schemapolicymutationresponse"></a>
<a id="schema_PolicyMutationResponse"></a>
<a id="tocSpolicymutationresponse"></a>
<a id="tocspolicymutationresponse"></a>

```json
{
  "policy": {
    "id": "P1",
    "name": "policy1",
    "version": 2
  }
}

```

Response for POST/PUT policy (create/update).

Mirrors GTA's `{"policy": {"id":"...", "name":"...", "version": 1}}`.
RBS is a stateless proxy — deserialized and passed through unchanged.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|policy|[PolicyMutation](#schemapolicymutation)|true|none|Mutation result.|

<h2 id="tocS_PolicyResponse">PolicyResponse</h2>
<!-- backwards compatibility -->
<a id="schemapolicyresponse"></a>
<a id="schema_PolicyResponse"></a>
<a id="tocSpolicyresponse"></a>
<a id="tocspolicyresponse"></a>

```json
{
  "policy_id": "string",
  "policy_name": "string",
  "policy_version": 0,
  "content_type": "string",
  "created_at": "string",
  "updated_at": "string",
  "applied_resources": [
    "string"
  ]
}

```

Policy response returned to callers.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|policy_id|string|true|none|none|
|policy_name|string|true|none|none|
|policy_version|integer(int32)|true|none|none|
|content_type|string|true|none|none|
|created_at|string|true|none|none|
|updated_at|string|true|none|none|
|applied_resources|array,null|false|none|none|

<h2 id="tocS_PolicyUpdateRequest">PolicyUpdateRequest</h2>
<!-- backwards compatibility -->
<a id="schemapolicyupdaterequest"></a>
<a id="schema_PolicyUpdateRequest"></a>
<a id="tocSpolicyupdaterequest"></a>
<a id="tocspolicyupdaterequest"></a>

```json
{
  "id": "P1",
  "name": "string",
  "description": "string",
  "attester_type": [
    "string"
  ],
  "content_type": "string",
  "content": "string",
  "is_default": true
}

```

Request body for PUT attestation policy (update).

`id` is required (collection-level operation, id in body not path).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|ID of the policy to update.|
|name|string,null|false|none|New name.|
|description|string,null|false|none|New description.|
|attester_type|array,null|false|none|New attester type list.|
|content_type|string,null|false|none|New content encoding.|
|content|string,null|false|none|New policy content.|
|is_default|boolean,null|false|none|Whether to set as default policy.|

<h2 id="tocS_RbcEvidenceItem">RbcEvidenceItem</h2>
<!-- backwards compatibility -->
<a id="schemarbcevidenceitem"></a>
<a id="schema_RbcEvidenceItem"></a>
<a id="tocSrbcevidenceitem"></a>
<a id="tocsrbcevidenceitem"></a>

```json
{
  "attester_type": "string",
  "evidence": null,
  "policy_ids": [
    "string"
  ],
  "ref_value_id": "string"
}

```

Single attestation artifact within a measurement (backend-specific detail).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|attester_type|string,null|false|none|Plugin or attester kind (e.g. tpm_boot).|
|evidence|any|false|none|Evidence payload (string or object per attestation backend).|
|policy_ids|array,null|false|none|Policy identifiers evaluated for this evidence.|
|ref_value_id|string,null|false|none|Optional reference value ID for precise baseline matching.<br>When present, GTA matches baseline by id+uid; when absent, by attester_type+uid.|

<h2 id="tocS_RbcEvidencesPayload">RbcEvidencesPayload</h2>
<!-- backwards compatibility -->
<a id="schemarbcevidencespayload"></a>
<a id="schema_RbcEvidencesPayload"></a>
<a id="tocSrbcevidencespayload"></a>
<a id="tocsrbcevidencespayload"></a>

```json
{
  "agent_version": "string",
  "measurements": [
    {
      "nonce": "string",
      "node_id": "string",
      "nonce_type": "string",
      "token_fmt": "string",
      "attester_data": {},
      "evidences": [
        {
          "attester_type": "string",
          "evidence": null,
          "policy_ids": [
            "string"
          ],
          "ref_value_id": "string"
        }
      ]
    }
  ]
}

```

Evidence JSON produced by RBC (`collect_evidence`) or equivalent.

Typical GTA-oriented shape includes a non-empty `measurements` array;
deployments may add other keys or per-backend wrappers.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|agent_version|string,null|false|none|Optional agent or collector version string.|
|measurements|[[RbcMeasurement](#schemarbcmeasurement)]|false|none|At least one entry required for standard attest flows; each entry carries nonce and evidences.|

<h2 id="tocS_RbcMeasurement">RbcMeasurement</h2>
<!-- backwards compatibility -->
<a id="schemarbcmeasurement"></a>
<a id="schema_RbcMeasurement"></a>
<a id="tocSrbcmeasurement"></a>
<a id="tocsrbcmeasurement"></a>

```json
{
  "nonce": "string",
  "node_id": "string",
  "nonce_type": "string",
  "token_fmt": "string",
  "attester_data": {},
  "evidences": [
    {
      "attester_type": "string",
      "evidence": null,
      "policy_ids": [
        "string"
      ],
      "ref_value_id": "string"
    }
  ]
}

```

One node or attestation unit inside the evidence bundle.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|nonce|string|true|none|Must equal the `nonce` field from GET /rbs/v0/challenge (same string, no transformation).|
|node_id|string,null|false|none|Optional node or workload identifier.|
|nonce_type|string,null|false|none|Optional hint for nonce interpretation (backend-specific).|
|token_fmt|string,null|false|none|Optional desired token format hint (backend-specific).|
|attester_data|any|false|none|none|

oneOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|null|false|none|none|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|[AttesterData](#schemaattesterdata)|false|none|Attester-supplied metadata for this measurement.|

continued

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|evidences|array,null|false|none|Collected attestation artifacts for this measurement.|

<h2 id="tocS_RbsVersion">RbsVersion</h2>
<!-- backwards compatibility -->
<a id="schemarbsversion"></a>
<a id="schema_RbsVersion"></a>
<a id="tocSrbsversion"></a>
<a id="tocsrbsversion"></a>

```json
{
  "service_name": "globaltrustauthority-rbs",
  "api_version": "0",
  "build": {
    "version": "0.1.0",
    "git_hash": "",
    "build_date": ""
  }
}

```

JSON emitted by `GET /rbs/version` (`service_name`, `api_version`, structured `build`).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|service_name|string|true|none|Logical service display name.|
|api_version|string|true|none|Published API contract version string.|
|build|[BuildMetadata](#schemabuildmetadata)|true|none|Build metadata (`version`, `git_hash`, `build_date`) for this binary; same shape as in the exported `OpenAPI` schema.|

<h2 id="tocS_RefValue">RefValue</h2>
<!-- backwards compatibility -->
<a id="schemarefvalue"></a>
<a id="schema_RefValue"></a>
<a id="tocSrefvalue"></a>
<a id="tocsrefvalue"></a>

```json
{
  "id": "rv-001",
  "uid": "test_01",
  "name": "tpm-baseline",
  "attester_type": "tpm",
  "description": "TPM reference baseline",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "jwt",
  "version": 1,
  "valid_code": 0
}

```

Reference value (baseline) entity returned by GTA.

RBS acts as a stateless proxy. `id`/`name`/`attester_type` are always
present in both GTA by_type/all (summary) and by_ids (full) responses,
so they are mandatory. `uid`/`description`/`content`/`content_type`/
`version`/`valid_code` appear only in the by_ids full response and are
optional.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|Stable ref_value identifier.|
|uid|string,null|false|none|User-scoped identifier (by_ids path only).|
|name|string|true|none|Human-readable baseline name.|
|attester_type|string|true|none|Attester type (e.g. tpm, tpm_ima, virt_cca).|
|description|string,null|false|none|Optional description (by_ids path only).|
|content|string,null|false|none|Baseline content (JWT or base64-encoded payload) (by_ids path only).|
|content_type|string,null|false|none|Content encoding: "jwt" (default) or "base64" (by_ids path only).|
|version|integer,null(int32)|false|none|Baseline version (by_ids path only).|
|valid_code|integer,null(int32)|false|none|Validity code: 0 = valid, 1 = invalid (by_ids path only).|

<h2 id="tocS_RefValueCreateRequest">RefValueCreateRequest</h2>
<!-- backwards compatibility -->
<a id="schemarefvaluecreaterequest"></a>
<a id="schema_RefValueCreateRequest"></a>
<a id="tocSrefvaluecreaterequest"></a>
<a id="tocsrefvaluecreaterequest"></a>

```json
{
  "name": "tpm-baseline",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "jwt",
  "description": "TPM reference baseline"
}

```

Request body for POST ref_value (create).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|name|string|true|none|Baseline name (non-empty).|
|attester_type|string|true|none|Attester type (non-empty).|
|content|string|true|none|Baseline content — JWT or base64-encoded payload (non-empty).|
|content_type|string,null|false|none|Content encoding: "jwt" (default) or "base64". When absent, GTA defaults to jwt.|
|description|string,null|false|none|Optional description.|

<h2 id="tocS_RefValueDeleteRequest">RefValueDeleteRequest</h2>
<!-- backwards compatibility -->
<a id="schemarefvaluedeleterequest"></a>
<a id="schema_RefValueDeleteRequest"></a>
<a id="tocSrefvaluedeleterequest"></a>
<a id="tocsrefvaluedeleterequest"></a>

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}

```

Request body for DELETE ref_value (batch delete).

GTA accepts `delete_type` = `"id"`/`"all"`/`"type"`, with
`attester_type` as the type filter.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|delete_type|[AttestationDeleteType](#schemaattestationdeletetype)|true|none|Delete mode.|
|ids|array,null|false|none|IDs to delete (required when `delete_type` is `Id`).|
|attester_type|string,null|false|none|Attester type filter (required when `delete_type` is `Type`).|

<h2 id="tocS_RefValueListResponse">RefValueListResponse</h2>
<!-- backwards compatibility -->
<a id="schemarefvaluelistresponse"></a>
<a id="schema_RefValueListResponse"></a>
<a id="tocSrefvaluelistresponse"></a>
<a id="tocsrefvaluelistresponse"></a>

```json
{
  "ref_values": [
    {
      "id": "rv-001",
      "uid": "test_01",
      "name": "tpm-baseline",
      "attester_type": "tpm",
      "description": "TPM reference baseline",
      "content": "eyJhbGciOiJSUzI1NiJ9...",
      "content_type": "jwt",
      "version": 1,
      "valid_code": 0
    }
  ],
  "total_count": 0
}

```

Paginated response for GET ref_value list.

`total_count`, `limit`, and `offset` are optional: present in by_type/all
paths, absent in by_ids paths.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|ref_values|[[RefValue](#schemarefvalue)]|true|none|List of ref_values matching the query.|
|total_count|integer,null(int64)|false|none|Total matching count (present in by_type/all paths; absent in by_ids path).|

<h2 id="tocS_RefValueMutation">RefValueMutation</h2>
<!-- backwards compatibility -->
<a id="schemarefvaluemutation"></a>
<a id="schema_RefValueMutation"></a>
<a id="tocSrefvaluemutation"></a>
<a id="tocsrefvaluemutation"></a>

```json
{
  "id": "rv-001",
  "name": "tpm-baseline",
  "version": 2
}

```

Inner mutation result for ref_value create/update.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|ID of the mutated ref_value.|
|name|string|true|none|Name of the mutated ref_value.|
|version|integer(int32)|true|none|New version after mutation.|

<h2 id="tocS_RefValueMutationResponse">RefValueMutationResponse</h2>
<!-- backwards compatibility -->
<a id="schemarefvaluemutationresponse"></a>
<a id="schema_RefValueMutationResponse"></a>
<a id="tocSrefvaluemutationresponse"></a>
<a id="tocsrefvaluemutationresponse"></a>

```json
{
  "ref_value": {
    "id": "rv-001",
    "name": "tpm-baseline",
    "version": 2
  }
}

```

Response for POST/PUT ref_value (create/update).

Mirrors GTA's `{"ref_value": {"id":"...", "name":"...", "version": 1}}`.
RBS is a stateless proxy — deserialized and passed through unchanged.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|ref_value|[RefValueMutation](#schemarefvaluemutation)|true|none|Mutation result.|

<h2 id="tocS_RefValueUpdateRequest">RefValueUpdateRequest</h2>
<!-- backwards compatibility -->
<a id="schemarefvalueupdaterequest"></a>
<a id="schema_RefValueUpdateRequest"></a>
<a id="tocSrefvalueupdaterequest"></a>
<a id="tocsrefvalueupdaterequest"></a>

```json
{
  "id": "rv-001",
  "name": "updated-baseline",
  "description": "string",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "base64"
}

```

Request body for PUT ref_value (update).

`id` is required (collection-level operation, id in body not path).
All other fields are optional; at least one should be provided.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|ID of the ref_value to update.|
|name|string,null|false|none|New name.|
|description|string,null|false|none|New description.|
|attester_type|string,null|false|none|New attester_type.|
|content|string,null|false|none|New content.|
|content_type|string,null|false|none|New content encoding.|

<h2 id="tocS_ResourceContentResponse">ResourceContentResponse</h2>
<!-- backwards compatibility -->
<a id="schemaresourcecontentresponse"></a>
<a id="schema_ResourceContentResponse"></a>
<a id="tocSresourcecontentresponse"></a>
<a id="tocsresourcecontentresponse"></a>

```json
{
  "uri": "string",
  "content": "string",
  "content_type": "string",
  "export_mode": "string"
}

```

Resource content returned by GET and POST .../retrieve.

`content` is always base64-encoded JWE ciphertext (Compact Serialization).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|uri|string|true|none|Canonical resource URI for the returned object.|
|content|string|true|none|Base64-encoded JWE ciphertext.|
|content_type|string,null|false|none|Original MIME type hint for decoding after JWE decryption.|
|export_mode|string|true|none|Export mode (currently always "jwe").|

<h2 id="tocS_ResourceInfoResponse">ResourceInfoResponse</h2>
<!-- backwards compatibility -->
<a id="schemaresourceinforesponse"></a>
<a id="schema_ResourceInfoResponse"></a>
<a id="tocSresourceinforesponse"></a>
<a id="tocsresourceinforesponse"></a>

```json
{
  "uri": "string",
  "user_id": "string",
  "policy_id": "string",
  "created_at": "string",
  "updated_at": "string",
  "content_type": "string",
  "export_mode": "string"
}

```

Resource metadata returned by GET .../info (no secret material).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|uri|string|true|none|none|
|user_id|string|true|none|none|
|policy_id|string|true|none|none|
|created_at|string|true|none|none|
|updated_at|string|true|none|none|
|content_type|string,null|false|none|none|
|export_mode|string|true|none|none|

<h2 id="tocS_ResourceResponse">ResourceResponse</h2>
<!-- backwards compatibility -->
<a id="schemaresourceresponse"></a>
<a id="schema_ResourceResponse"></a>
<a id="tocSresourceresponse"></a>
<a id="tocsresourceresponse"></a>

```json
{
  "uri": "string",
  "provider_name": "string",
  "repository_name": "string",
  "resource_type": "string",
  "resource_name": "string",
  "created_at": "string",
  "updated_at": "string",
  "content_type": "string",
  "export_mode": "string",
  "policy_id": "string",
  "additional_info": "string"
}

```

Resource metadata returned after create or update.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|uri|string|true|none|none|
|provider_name|string|true|none|none|
|repository_name|string|true|none|none|
|resource_type|string|true|none|none|
|resource_name|string|true|none|none|
|created_at|string|true|none|none|
|updated_at|string|true|none|none|
|content_type|string,null|false|none|none|
|export_mode|string|true|none|none|
|policy_id|string|true|none|none|
|additional_info|string,null|false|none|none|

<h2 id="tocS_Role">Role</h2>
<!-- backwards compatibility -->
<a id="schemarole"></a>
<a id="schema_Role"></a>
<a id="tocSrole"></a>
<a id="tocsrole"></a>

```json
"admin"

```

User role. `Admin` is pre-configured and cannot be created via the API.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|User role. `Admin` is pre-configured and cannot be created via the API.|

#### Enumerated Values

|Property|Value|
|---|---|
|*anonymous*|admin|
|*anonymous*|user|

<h2 id="tocS_UpdatePolicyRequest">UpdatePolicyRequest</h2>
<!-- backwards compatibility -->
<a id="schemaupdatepolicyrequest"></a>
<a id="schema_UpdatePolicyRequest"></a>
<a id="tocSupdatepolicyrequest"></a>
<a id="tocsupdatepolicyrequest"></a>

```json
{
  "name": "string",
  "content_type": "string",
  "content": "string"
}

```

Policy update request body.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|name|string|true|none|none|
|content_type|string|true|none|none|
|content|string|true|none|none|

<h2 id="tocS_UpdateResourceRequest">UpdateResourceRequest</h2>
<!-- backwards compatibility -->
<a id="schemaupdateresourcerequest"></a>
<a id="schema_UpdateResourceRequest"></a>
<a id="tocSupdateresourcerequest"></a>
<a id="tocsupdateresourcerequest"></a>

```json
{
  "policy_id": "string",
  "content_type": "string",
  "export_mode": "string",
  "additional_info": "string"
}

```

Request body for `PUT /rbs/v0/{uri}` — update or create a resource.

`policy_id` is optional on update: an explicit value rebinds the resource to
a new policy (validated as usual); omitting it keeps the existing resource's
binding. A brand-new resource created via the upsert path still requires an
explicit `policy_id`.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|policy_id|string,null|false|none|none|
|content_type|string,null|false|none|none|
|export_mode|string,null|false|none|none|
|additional_info|string,null|false|none|none|

<h2 id="tocS_UserCreateRequest">UserCreateRequest</h2>
<!-- backwards compatibility -->
<a id="schemausercreaterequest"></a>
<a id="schema_UserCreateRequest"></a>
<a id="tocSusercreaterequest"></a>
<a id="tocsusercreaterequest"></a>

```json
{
  "username": "string",
  "role": {},
  "enabled": true,
  "auth_type": "jwt",
  "public_key": "string",
  "jwk": null
}

```

Request body for POST /rbs/v0/users (create user).

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|username|string|true|none|Login or unique handle. Immutable.|
|role|any|false|none|none|

oneOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|null|false|none|none|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|[Role](#schemarole)|false|none|Optional role; only `user` is allowed via API (admin is pre-configured).|

continued

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|enabled|boolean,null|false|none|Whether the account is enabled.|
|auth_type|[AuthType](#schemaauthtype)|true|none|Authentication type.|
|public_key|string,null|false|none|Base64-encoded PEM public key (mutually exclusive with `jwk`).|
|jwk|any|false|none|JWK public key JSON object (mutually exclusive with `public_key`).|

<h2 id="tocS_UserListResponse">UserListResponse</h2>
<!-- backwards compatibility -->
<a id="schemauserlistresponse"></a>
<a id="schema_UserListResponse"></a>
<a id="tocSuserlistresponse"></a>
<a id="tocsuserlistresponse"></a>

```json
{
  "users": [
    {
      "id": "string",
      "username": "string",
      "role": "admin",
      "enabled": true,
      "created_at": "string",
      "updated_at": "string"
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}

```

Paginated response for GET /rbs/v0/users.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|users|[[UserResponse](#schemauserresponse)]|true|none|Page of users.|
|total_count|integer(int64)|true|none|Total matching users (not only this page).|
|limit|integer(int64)|true|none|Effective page size (may mirror request `limit`).|
|offset|integer(int64)|true|none|Effective skip count (may mirror request `offset`).|

<h2 id="tocS_UserResponse">UserResponse</h2>
<!-- backwards compatibility -->
<a id="schemauserresponse"></a>
<a id="schema_UserResponse"></a>
<a id="tocSuserresponse"></a>
<a id="tocsuserresponse"></a>

```json
{
  "id": "string",
  "username": "string",
  "role": "admin",
  "enabled": true,
  "created_at": "string",
  "updated_at": "string"
}

```

Response for user retrieval, creation, and update.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|Stable user ID (UUID).|
|username|string|true|none|Human-facing login or handle.|
|role|[Role](#schemarole)|true|none|User role.|
|enabled|boolean|true|none|Whether the account is enabled.|
|created_at|string|true|none|Creation time (RFC 3339).|
|updated_at|string|true|none|Last modification time (RFC 3339).|

<h2 id="tocS_UserUpdateRequest">UserUpdateRequest</h2>
<!-- backwards compatibility -->
<a id="schemauserupdaterequest"></a>
<a id="schema_UserUpdateRequest"></a>
<a id="tocSuserupdaterequest"></a>
<a id="tocsuserupdaterequest"></a>

```json
{
  "role": {},
  "enabled": true,
  "auth_type": {},
  "public_key": "string",
  "jwk": null
}

```

Request body for PUT /rbs/v0/users/{username} (update user).

All fields are optional, but at least one must be provided.
`username` is NOT in the request body — it is immutable.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|role|any|false|none|none|

oneOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|null|false|none|none|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|[Role](#schemarole)|false|none|New role (admin only). The `admin` role is pre-configured and not<br>API-assignable: assigning it to a non-built-in target is rejected with<br>`admin role is pre-configured and not API-assignable` (403); the built-in<br>Administrator may only keep `role: "admin"` (a no-op, 200) — any other<br>role is rejected with `cannot modify 'role' of the built-in<br>administrator` (403). A non-admin self-update sending its current role<br>(`user`) is a no-op (200); any other role is rejected with `self-update<br>may not modify 'role'` (403).|

continued

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|enabled|boolean,null|false|none|Whether the account can authenticate. A non-admin self-update may set<br>this to `true` (a no-op) but may **not** disable itself; `false` is<br>rejected with `self-update may not modify 'enabled'` (403).|
|auth_type|any|false|none|none|

oneOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|null|false|none|none|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|[AuthType](#schemaauthtype)|false|none|Authentication type.|

continued

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|public_key|string,null|false|none|Base64-encoded PEM public key (mutually exclusive with `jwk`).|
|jwk|any|false|none|JWK public key JSON object (mutually exclusive with `public_key`).|

