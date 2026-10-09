# Network request vetting

This example vets an incoming client before a webhook registration is accepted. It checks the client IP address against known threat, bot and Tor exit node lists, then checks the callback URL for server-side request forgery risk.

## Prerequisites

1. A Cloudmersive API key. See the setup guide in the connector README.

2. Create a `Config.toml` file in the example directory with the following values.

```toml
apiKey = "<API_KEY>"
clientIp = "<CLIENT_IP_ADDRESS>"
callbackUrl = "<CALLBACK_URL>"
```

Optionally, set `blockedDomains` to a list of domains that the SSRF check must treat as blocked.

## Run the example

Execute the following command to run the example.

```bash
bal run
```
