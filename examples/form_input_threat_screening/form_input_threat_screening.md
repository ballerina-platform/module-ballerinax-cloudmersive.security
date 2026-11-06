# Form input threat screening

This example screens a user-submitted form field before it is stored. It runs the automatic threat detector, confirms whether the input is a SQL injection attempt, and normalizes any cross-site scripting content so the remaining text can be kept.

## Prerequisites

1. A Cloudmersive API key. See the setup guide in the connector README.

2. Create a `Config.toml` file in the example directory with the following values.

```toml
apiKey = "<API_KEY>"
userInput = "<TEXT_TO_SCREEN>"
```

## Run the example

Execute the following command to run the example.

```bash
bal run
```
