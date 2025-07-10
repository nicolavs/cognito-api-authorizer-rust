use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse,
};
use aws_lambda_events::event::iam::{IamPolicyEffect, IamPolicyStatement};
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use once_cell::sync::OnceCell;
use serde_json::Value;
use std::env;
use std::sync::Arc;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

// Global static reference to the Secrets Manager client
static SECRETS_MANAGER_CLIENT: OnceCell<Arc<SecretsManagerClient>> = OnceCell::new();

// Function to get a secret from AWS Secrets Manager
async fn get_secret(secret_name: &str) -> Result<String, Error> {
    // Check if we're in test mode
    if env::var("RUST_LAMBDA_TEST_MODE").is_ok() {
        // In test mode, return a test API key
        return Ok("test-api-key".to_string());
    }

    // Get the client from the global static reference
    let client = SECRETS_MANAGER_CLIENT
        .get()
        .ok_or_else(|| Error::from("Secrets Manager client not initialized"))?;

    // Get the secret
    let secret_response = client
        .get_secret_value()
        .secret_id(secret_name)
        .send()
        .await?;

    // Extract the secret string
    if let Some(secret_string) = secret_response.secret_string() {
        Ok(secret_string.to_string())
    } else {
        Err(Error::from("Secret value not found"))
    }
}

// Create a policy document based on the effect (Allow or Deny)
fn create_policy(effect: IamPolicyEffect, method_arn: &str) -> ApiGatewayCustomAuthorizerPolicy {
    ApiGatewayCustomAuthorizerPolicy {
        version: Some("2012-10-17".to_string()),
        statement: vec![IamPolicyStatement {
            action: vec!["execute-api:Invoke".to_string()],
            effect,
            resource: vec![method_arn.to_string()],
            ..Default::default()
        }],
    }
}

// Export the function handler for testing
pub async fn function_handler(
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse, Error> {
    let (request, _context) = event.into_parts();

    // Log the entire request for debugging
    info!("Received authorizer request: {:?}", request);

    // Get the method ARN
    let method_arn = request.method_arn.clone().unwrap_or_else(|| "".to_string());

    // Extract the authorization token from headers
    let auth_header = if let Some(header) = request
        .headers
        .get("Authorization")
        .or_else(|| request.headers.get("authorization"))
    {
        info!("Authorization header: {:?}", header);
        header.to_str().unwrap_or("").to_string()
    } else {
        info!("No authorization token found");
        "".to_string()
    };

    // Check if the auth header starts with "Bearer "
    if !auth_header.starts_with("Bearer ") {
        // If not a Bearer token, check if it matches the API key
        let secret_name =
            env::var("API_KEY_SECRET_NAME").unwrap_or_else(|_| "api-key-secret".to_string());

        return match get_secret(&secret_name).await {
            Ok(api_key) => {
                if auth_header == api_key {
                    info!("API key validation successful");
                    // Create an allow policy
                    let policy = create_policy(IamPolicyEffect::Allow, &method_arn);

                    let response = ApiGatewayCustomAuthorizerResponse {
                        principal_id: Some("apikey".to_string()),
                        policy_document: policy,
                        context: Value::Null,
                        usage_identifier_key: None,
                    };

                    Ok(response)
                } else {
                    warn!("API key validation failed");
                    // Create a deny policy
                    let policy = create_policy(IamPolicyEffect::Deny, &method_arn);

                    let response = ApiGatewayCustomAuthorizerResponse {
                        principal_id: Some("unauthorized".to_string()),
                        policy_document: policy,
                        context: Value::Null,
                        usage_identifier_key: None,
                    };

                    Ok(response)
                }
            }
            Err(err) => {
                warn!("Failed to retrieve API key secret: {:?}", err);
                // Create a deny policy
                let policy = create_policy(IamPolicyEffect::Deny, &method_arn);

                let response = ApiGatewayCustomAuthorizerResponse {
                    principal_id: Some("error".to_string()),
                    policy_document: policy,
                    context: Value::Null,
                    usage_identifier_key: None,
                };

                Ok(response)
            }
        };
    }

    // For JWT tokens (starting with "Bearer "), we'll implement validation in a future step
    // For now, just return an allow policy
    info!("Bearer token found, but validation not implemented yet");
    let policy = create_policy(IamPolicyEffect::Allow, &method_arn);

    let response = ApiGatewayCustomAuthorizerResponse {
        principal_id: Some("user".to_string()),
        policy_document: policy,
        context: Value::Null,
        usage_identifier_key: None,
    };

    Ok(response)
}

// Initialize the Secrets Manager client
async fn init_secrets_manager_client() -> Result<(), Error> {
    // Create AWS config
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;

    // Create Secrets Manager client
    let client = SecretsManagerClient::new(&config);

    // Store the client in the global static reference
    SECRETS_MANAGER_CLIENT
        .set(Arc::new(client))
        .map_err(|_| Error::from("Failed to initialize Secrets Manager client"))?;

    Ok(())
}

// Only include the main function when building as a binary, not as a library
#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize the tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Lambda function starting up");

    // Initialize the Secrets Manager client
    init_secrets_manager_client().await?;
    info!("Secrets Manager client initialized");

    // Start the Lambda runtime
    lambda_runtime::run(service_fn(function_handler)).await?;

    Ok(())
}
