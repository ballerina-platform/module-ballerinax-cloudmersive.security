## Overview

[Cloudmersive](https://cloudmersive.com/) is a cloud API platform, and its Security API helps you detect and block security threats in application input and network traffic. It supports version `v1` of the Security API.

The Cloudmersive Security connector lets Ballerina applications call these threat detection operations directly.

### Key features

- Detect SQL injection, cross-site scripting (XSS), XML external entity (XXE) and insecure deserialization attacks in text input
- Automatically scan input for a wide range of threat types in a single call
- Normalize text input to remove cross-site scripting content
- Check URLs for server-side request forgery (SSRF) risks
- Check IP addresses against known threat lists, bot lists and Tor exit nodes

## Setup guide

To use the Cloudmersive Security connector, you need an API key.

1. Create a [Cloudmersive account](https://account.cloudmersive.com/signup) or log in to an existing one.

2. Open the **API Keys** section of the account dashboard.

3. Copy an existing API key or create a new one.

## Quickstart

To use the `cloudmersive.security` connector in your Ballerina application, update the `.bal` file as follows:

### Step 1: Import the module

```ballerina
import ballerinax/cloudmersive.security;
```

### Step 2: Instantiate a new connector

Create a `Config.toml` file with your API key.

```toml
apiKey = "<API_KEY>"
```

Then create a client using the configurable.

```ballerina
configurable string apiKey = ?;

final security:Client securityClient = check new ({apikey: apiKey});
```

### Step 3: Invoke the connector operation

Check an IP address against the known threat lists. The API expects the IP address as a JSON string, so encode it first.

```ballerina
public function main() returns error? {
    security:IpThreatResponse _ = check securityClient->checkIpThreat("55.55.55.55".toJsonString());
}
```

### Step 4: Run the Ballerina application

```bash
bal run
```

## Examples

The `Cloudmersive Security` connector provides practical examples illustrating usage in various scenarios. Explore these [examples](https://github.com/ballerina-platform/module-ballerinax-cloudmersive.security/tree/main/examples/), covering the following use cases:

1. [Form input threat screening](../examples/form_input_threat_screening/form_input_threat_screening.md) - Screen a submitted form field for injection and scripting attacks before storing it.
2. [Network request vetting](../examples/network_request_vetting/network_request_vetting.md) - Vet a client IP address and a callback URL before accepting a webhook registration.
