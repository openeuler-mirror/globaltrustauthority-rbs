<!-- Generator: Widdershins v4.0.1 -->

<h1 id="rbs-rest-api">RBS REST API v0</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

Resource Broker Service (RBS) HTTP API.

Base URLs:

* <a href="http://localhost:6666">http://localhost:6666</a>

Web: <a href="https://gitcode.com/openeuler/globaltrustauthority-rbs">RBS open-source community</a> 
License: <a href="http://license.coscl.org.cn/MulanPSL2">Mulan Permissive Software License, Version 2</a>

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

# Schemas

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
|build|[BuildMetadata](#schemabuildmetadata)|true|none|Build-time identity for the running binary.|

