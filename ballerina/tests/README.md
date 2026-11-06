# Running Tests

## Prerequisites

You need a Cloudmersive API key to run the tests against the live API. The tests run against a mock server by default and need no credentials.

## Test environments

There are two test environments for running the connector tests:

| Test environment | Description                                                                      |
|------------------|----------------------------------------------------------------------------------|
| Mock server      | A mock service in `tests/mock_service.bal` that returns realistic sample data.   |
| Cloudmersive API | The live Cloudmersive Security API.                                              |

## Running the tests

1. Navigate to the `ballerina` directory.

2. To run the tests against the mock server, execute:

    ```bash
    bal test --groups mock_tests
    ```

3. To run the tests against the live API, set the following environment variables and execute the live test group:

    ```bash
    export IS_LIVE_SERVER=true
    export CLOUDMERSIVE_API_KEY=<API_KEY>
    bal test --groups live_tests
    ```

The test suite covers all nine operations: automatic threat detection, insecure deserialization, SQL injection, XSS and XXE checks, SSRF URL detection, and the IP threat, bot and Tor node checks.
