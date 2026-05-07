<!-- Generator: Widdershins v4.0.1 -->

<h1 id="rbs-rest-api">RBS REST API v0</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

Resource Broker Service (RBS) HTTP API.

Base URLs:

* <a href="http://localhost:6666">http://localhost:6666</a>

Web: <a href="https://gitcode.com/openeuler/globaltrustauthority-rbs">RBS open-source community</a> 
License: <a href="http://license.coscl.org.cn/MulanPSL2">Mulan Permissive Software License, Version 2</a>

# Authentication

- HTTP Authentication, scheme: bearer JWT Bearer Token. Obtain via Admin API or attestation.

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
    "build_date": "2026-04-20T00:00:00Z"
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
|limit|query|integer(int64)|false|Page size (1..100, default 50)|
|offset|query|integer(int64)|false|Offset (>=0, default 0)|

> Example responses

> 200 Response

```json
{
  "items": [
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
|403|[Forbidden](https://tools.ietf.org/html/rfc7231#section-6.5.3)|Forbidden|[ErrorBody](#schemaerrorbody)|
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

# Schemas

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
  "build_date": "2026-04-20T00:00:00Z"
}

```

Build-time identity for the running binary.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|version|string|true|none|Cargo package / release version (semver).|
|git_hash|string|true|none|Git commit hash at build time (hex), or empty when not embedded at build.|
|build_date|string|true|none|Build timestamp (UTC), typically RFC 3339, or empty when not embedded at build.|

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
    "build_date": "2026-04-20T00:00:00Z"
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
|public_key|string,null|false|none|PEM-encoded public key (mutually exclusive with `jwk`).|
|jwk|any|false|none|JWK public key object (mutually exclusive with `public_key`).|

<h2 id="tocS_UserListResponse">UserListResponse</h2>
<!-- backwards compatibility -->
<a id="schemauserlistresponse"></a>
<a id="schema_UserListResponse"></a>
<a id="tocSuserlistresponse"></a>
<a id="tocsuserlistresponse"></a>

```json
{
  "items": [
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
|items|[[UserResponse](#schemauserresponse)]|true|none|Page of users.|
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
|» *anonymous*|[Role](#schemarole)|false|none|New role (admin users only).|

continued

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|enabled|boolean,null|false|none|Whether the account can authenticate.|
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
|public_key|string,null|false|none|PEM-encoded public key (mutually exclusive with `jwk`).|
|jwk|any|false|none|JWK public key object (mutually exclusive with `public_key`).|

