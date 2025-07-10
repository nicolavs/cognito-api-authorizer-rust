# Cognito API Authorizer (Rust)

A serverless AWS Lambda function written in Rust that serves as an API Gateway authorizer, validating both API keys and Cognito JWT tokens.

## Overview

This Lambda function acts as a custom authorizer for API Gateway, providing two authentication methods:
1. **API Key Authentication**: Validates API keys against a secret stored in AWS Secrets Manager
2. **JWT Token Authentication**: Validates JWT tokens issued by Amazon Cognito

The authorizer generates IAM policies that either allow or deny access to API Gateway endpoints based on the authentication result.

## Features

- **Dual Authentication Support**: Handles both API keys and JWT tokens
- **API Key Validation**: Securely validates API keys against AWS Secrets Manager
- **JWT Token Validation**: Verifies JWT tokens issued by Amazon Cognito
- **Token Expiration Check**: Ensures JWT tokens are not expired
- **Efficient Client Management**: Uses static references for AWS clients to optimize performance
- **Comprehensive Testing**: Includes test cases for all authentication scenarios

## How It Works

### Authentication Flow

1. The Lambda function receives an authorization request from API Gateway
2. It extracts the authorization header from the request
3. If the header doesn't start with "Bearer ", it's treated as an API key:
   - The function retrieves the expected API key from AWS Secrets Manager
   - It compares the provided key with the expected key
   - Access is granted if they match, denied otherwise
4. If the header starts with "Bearer ", it's treated as a JWT token:
   - The function verifies the token with Amazon Cognito
   - It checks if the token is expired
   - Access is granted if the token is valid and not expired, denied otherwise

### Policy Generation

The function generates an IAM policy document that:
- Allows or denies the `execute-api:Invoke` action
- Applies to the specific API Gateway method ARN from the request
- Includes a principal ID based on the authentication result

## Setup and Deployment

### Prerequisites

- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
- [Rust](https://www.rust-lang.org/tools/install)
- [cargo-lambda](https://github.com/cargo-lambda/cargo-lambda)

### Environment Variables

The Lambda function requires the following environment variables:
- `API_KEY_SECRET_NAME`: Name of the secret in AWS Secrets Manager containing the API key
- `COGNITO_USER_POOL_ID`: ID of the Cognito User Pool
- `COGNITO_APP_CLIENT_ID`: ID of the Cognito App Client

These are configured in the `template.yaml` file.

### Deployment

1. Build the application:
   ```bash
   sam build
   ```

2. Deploy the application:
   ```bash
   sam deploy --guided
   ```

3. Follow the prompts to configure the deployment parameters.

## Testing

The project includes test cases for:
- Valid API key authentication
- Invalid API key authentication
- Valid JWT token authentication
- Expired JWT token authentication

Run the tests with:
```bash
cd rust_app
cargo test
```

## Local Testing

You can test the function locally using the provided sample event:

```bash
sam local invoke AuthorizerFunction --event events/authorizer-event.json
```

## Integration with API Gateway

To use this authorizer with your API Gateway:

1. Deploy this Lambda function
2. In the API Gateway console, create a new authorizer
3. Select the Lambda function as the authorizer
4. Configure the authorizer to use the REQUEST type
5. Set the identity source to the header containing your authorization token (e.g., `Authorization`)
6. Apply the authorizer to your API routes
