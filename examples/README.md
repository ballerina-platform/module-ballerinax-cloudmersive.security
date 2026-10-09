# Examples

The `ballerinax/cloudmersive.security` connector provides practical examples illustrating usage in various scenarios.

1. [Form input threat screening](./form_input_threat_screening/form_input_threat_screening.md) - Screen a submitted form field for injection and scripting attacks before storing it.
2. [Network request vetting](./network_request_vetting/network_request_vetting.md) - Vet a client IP address and a callback URL before accepting a webhook registration.

## Prerequisites

Obtain a Cloudmersive API key and provide it, together with the example's other values, in a `Config.toml` file in the example directory. See each example's document for details.

## Running an example

Execute the following commands to build an example from the source:

* To build an example:

    ```bash
    bal build
    ```

* To run an example:

    ```bash
    bal run
    ```

## Building the examples with the local module

**Warning**: Due to the absence of support for reading local repositories for single Ballerina files, the Bala of the module is manually written to the central repository as a workaround. Consequently, the bash script may modify your local Ballerina repositories.

Execute the following commands to build all the examples against the changes you have made to the module locally:

* To build all the examples:

    ```bash
    ./build.sh build
    ```

* To run all the examples:

    ```bash
    ./build.sh run
    ```
