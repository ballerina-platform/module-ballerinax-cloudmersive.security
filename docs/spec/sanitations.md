_Author_:  @DimuthuMadushan \
_Created_: 2026/10/09 \
_Updated_: 2026/10/09 \
_Edition_: Swan Lake

# Sanitation for OpenAPI specification

This document records the sanitation done on top of the official OpenAPI specification from Cloudmersive Security. 
The OpenAPI specification is obtained from [`wso2/api-specs`](https://github.com/wso2/api-specs/blob/main/openapi/cloudmersive/security/v1/openapi.json).
These changes are done in order to improve the overall usability, and as workarounds for some known language limitations.


1. Update the API Paths
- **Original**: Paths included common prefix `/security/threat-detection` in each endpoint.
- **Updated**: Common prefix removed from endpoints as it is now in the base URL.
- **Reason**: Simplifies API paths and avoids duplication.
<!-- auto-generated -->

2. Fix the doubled slash in the server URL
- **Original**: After `align` folds the common path prefix into the server URL, it reads `https://api.cloudmersive.com//security/threat-detection`.
- **Updated**: The server URL is `https://api.cloudmersive.com/security/threat-detection`. This is a hand edit to the aligned spec (`aligned_ballerina_openapi.json`) and must be re-applied after a re-align.
- **Reason**: The doubled slash would be baked into the client's default `serviceUrl`.

3. Describe the 200 response of every operation
- **Original**: Every operation's `200` response was described only as `OK`.
- **Updated**: Each response now says what it returns, for example `Result of the SQL injection check` (all 9 operations, edited in the original spec).
- **Reason**: A generic `OK` gives no information on what the response contains.

4. Add a description to the `CleanResult` property
- **Original**: `StringAutomaticThreatDetection.CleanResult` had no description.
- **Updated**: Added `True if the input contained no detected threats, false otherwise`.
- **Reason**: Every other property of the schema is documented.

5. Rename operations and schemas
- **Original**: Operation IDs followed the `Group_OperationName` pattern, and schemas carried `String`, `Url` and `ThreatDetection` prefixes and `Full` suffixes.
- **Updated**: Operation IDs: `ContentThreatDetection_AutomaticThreatDetectionString` to `detectThreats`, `ContentThreatDetection_DetectInsecureDeserializationJsonString` to `detectInsecureDeserialization`, `ContentThreatDetection_CheckSqlInjectionString` to `checkSqlInjection`, `ContentThreatDetection_ProtectXss` to `protectXss`, `ContentThreatDetection_CheckXxe` to `checkXxe`, `NetworkThreatDetection_DetectSsrfUrl` to `detectSsrf`, `NetworkThreatDetection_IsThreat` to `checkIpThreat`, `NetworkThreatDetection_IsBot` to `checkIpBot`, `NetworkThreatDetection_IsTorNode` to `checkIpTorNode`. Schemas: `IPThreatDetectionResponse` to `IpThreatResponse`, `StringAutomaticThreatDetection` to `AutomaticThreatDetectionResult`, `StringInsecureDeserializationJsonDetection` to `InsecureDeserializationResult`, `StringSqlInjectionDetectionResult` to `SqlInjectionResult`, `StringXssProtectionResult` to `XssProtectionResult`, `StringXxeDetectionResult` to `XxeDetectionResult`, `ThreatDetectionBotCheckResponse` to `BotCheckResponse`, `ThreatDetectionTorNodeResponse` to `TorNodeCheckResponse`, `UrlSsrfThreatDetectionRequestFull` to `SsrfDetectionRequest`, `UrlSsrfThreatDetectionResponseFull` to `SsrfDetectionResponse`.
- **Reason**: Concise, intent-revealing names. The decisions are persisted in `ai-mappings.json`.

6. Use the production host
- **Original**: `host` was `testapi.cloudmersive.com`, Cloudmersive's test endpoint.
- **Updated**: `host` is `api.cloudmersive.com`, edited in the original spec, so the client's default `serviceUrl` is `https://api.cloudmersive.com/security/threat-detection`.
- **Reason**: Consistent with the other Cloudmersive connectors (`barcode`, `currency`, `validate`), which target the production API.

## OpenAPI cli command

The following command was used to generate the Ballerina client from the OpenAPI specification. The command should be executed from the repository root directory.

```bash
bal openapi -i docs/spec/aligned_ballerina_openapi.json -o ballerina --mode client --client-methods remote --license docs/license.txt
```

Note: The license year is hardcoded to 2024, change if necessary.
