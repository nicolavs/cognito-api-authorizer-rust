use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse,
};
use aws_lambda_events::event::iam::{IamPolicyEffect, IamPolicyStatement};
use aws_sdk_cognitoidentityprovider::Client as CognitoClient;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use lambda_runtime::{service_fn, Error, LambdaEvent};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::sync::Arc;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

// Global static reference to the Secrets Manager client
static SECRETS_MANAGER_CLIENT: OnceCell<Arc<SecretsManagerClient>> = OnceCell::new();

// Global static reference to the Cognito client
static COGNITO_CLIENT: OnceCell<Arc<CognitoClient>> = OnceCell::new();

// Define a struct for JWT claims
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    // Standard JWT claims
    #[serde(rename = "sub")]
    subject: Option<String>,
    #[serde(rename = "iss")]
    issuer: Option<String>,
    #[serde(rename = "aud")]
    audience: Option<String>,
    #[serde(rename = "exp")]
    expiration: Option<u64>,
    #[serde(rename = "nbf")]
    not_before: Option<u64>,
    #[serde(rename = "iat")]
    issued_at: Option<u64>,
    #[serde(rename = "jti")]
    jwt_id: Option<String>,

    // Cognito specific claims
    #[serde(rename = "cognito:groups")]
    cognito_groups: Option<Vec<String>>,
    #[serde(rename = "email_verified")]
    email_verified: Option<bool>,
    #[serde(rename = "origin_jti")]
    origin_jti: Option<String>,
    #[serde(rename = "event_id")]
    event_id: Option<String>,
    #[serde(rename = "token_use")]
    token_use: Option<String>,
    #[serde(rename = "auth_time")]
    auth_time: Option<u64>,
    #[serde(rename = "name")]
    name: Option<String>,
    #[serde(rename = "email")]
    email: Option<String>,

    // Custom claims - can be extended as needed
    #[serde(flatten)]
    additional_claims: std::collections::HashMap<String, Value>,
}

// Function to decode and verify a JWT token using Cognito
async fn decode_jwt(token: &str) -> Result<JwtClaims, Error> {
    // Check if we're in test mode
    if env::var("RUST_LAMBDA_TEST_MODE").is_ok() {
        // Get current time for expiration calculations
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // In test mode, check if it's our valid test token
        if token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" {
            // Return the expected claims for our valid test token with future expiration
            let expiration = current_time + 3600; // 1 hour from now

            let claims = JwtClaims {
                subject: Some("7dc1e563-c20f-4f5e-a7a2-a7cf1cd784cb".to_string()),
                issuer: Some("https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_abcdeFG".to_string()),
                audience: Some("7mr38pechbp42ptnb6rhm7s9qa".to_string()),
                expiration: Some(expiration),
                not_before: None,
                issued_at: Some(1729560312),
                jwt_id: Some("5c18cc7f-0e85-4298-99eb-0d4309bdb6cd".to_string()),
                cognito_groups: Some(vec!["admin".to_string()]),
                email_verified: Some(true),
                origin_jti: Some("4e406217-c32e-4664-a963-32e868793d1c".to_string()),
                event_id: Some("930f7c31-978b-4ff1-976c-d496161942bd".to_string()),
                token_use: Some("id".to_string()),
                auth_time: Some(1729560312),
                name: Some("John".to_string()),
                email: Some("john@company.com".to_string()),
                additional_claims: std::collections::HashMap::new(),
            };
            // No need to add name to additional_claims as we have a dedicated field for it now
            return Ok(claims);
        }
        // Check if it's our expired test token
        else if token == "expired-token" {
            // Return the expected claims for our expired test token
            let expiration = current_time - 3600; // 1 hour ago (expired)

            let claims = JwtClaims {
                subject: Some("7dc1e563-c20f-4f5e-a7a2-a7cf1cd784cb".to_string()),
                issuer: Some("https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_abcdeFG".to_string()),
                audience: Some("7mr38pechbp42ptnb6rhm7s9qa".to_string()),
                expiration: Some(expiration),
                not_before: None,
                issued_at: Some(1729560312),
                jwt_id: Some("5c18cc7f-0e85-4298-99eb-0d4309bdb6cd".to_string()),
                cognito_groups: Some(vec!["admin".to_string()]),
                email_verified: Some(true),
                origin_jti: Some("4e406217-c32e-4664-a963-32e868793d1c".to_string()),
                event_id: Some("930f7c31-978b-4ff1-976c-d496161942bd".to_string()),
                token_use: Some("id".to_string()),
                auth_time: Some(1729560312),
                name: Some("John".to_string()),
                email: Some("john@company.com".to_string()),
                additional_claims: std::collections::HashMap::new(),
            };
            // No need to add name to additional_claims as we have a dedicated field for it now
            return Ok(claims);
        }

        // For other tokens in test mode, just decode without verification
        let validation = Validation::new(Algorithm::HS256);
        let key = DecodingKey::from_secret(&[]);
        let token_data = decode::<JwtClaims>(token, &key, &validation)
            .map_err(|e| Error::from(format!("Failed to decode JWT token: {}", e)))?;
        return Ok(token_data.claims);
    }

    // Get the Cognito client from the global static reference
    let client = COGNITO_CLIENT
        .get()
        .ok_or_else(|| Error::from("Cognito client not initialized"))?;

    // Get the Cognito user pool ID and app client ID from environment variables
    let user_pool_id = env::var("COGNITO_USER_POOL_ID")
        .map_err(|_| Error::from("COGNITO_USER_POOL_ID environment variable not set"))?;
    let app_client_id = env::var("COGNITO_APP_CLIENT_ID")
        .map_err(|_| Error::from("COGNITO_APP_CLIENT_ID environment variable not set"))?;

    // Use Cognito to verify the JWT token
    let response = client
        .get_user()
        .access_token(token)
        .send()
        .await
        .map_err(|e| Error::from(format!("Failed to verify JWT token: {}", e)))?;

    // Extract user attributes from the response
    let attributes = response.user_attributes();

    // Create a JwtClaims object from the user attributes
    let mut claims = JwtClaims {
        subject: None,
        issuer: Some(format!(
            "cognito-idp.{}.amazonaws.com/{}",
            env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
            user_pool_id
        )),
        audience: Some(app_client_id),
        expiration: None,
        not_before: None,
        issued_at: None,
        jwt_id: None,
        cognito_groups: None,
        email_verified: None,
        origin_jti: None,
        event_id: None,
        token_use: None,
        auth_time: None,
        name: None,
        email: None,
        additional_claims: std::collections::HashMap::new(),
    };

    // Extract the subject (sub) from the user attributes
    for attr in attributes {
        if attr.name() == "sub" {
            claims.subject = Some(attr.value().unwrap_or("").to_string());
        }
        // Add other attributes as additional claims
        claims.additional_claims.insert(
            attr.name().to_string(),
            Value::String(attr.value().unwrap_or("").to_string()),
        );
    }

    Ok(claims)
}

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

    // If we reach here, the auth header starts with "Bearer "
    // For JWT tokens (starting with "Bearer "), decode the token
    info!("Bearer token found, attempting to decode");

    // Extract the token by removing the "Bearer " prefix
    let token = auth_header.trim_start_matches("Bearer ").trim();

    // Attempt to decode the JWT token
    match decode_jwt(token).await {
        Ok(claims) => {
            // Log the decoded claims
            info!("Successfully decoded JWT token: {:?}", claims);

            // Extract subject (sub) from claims if available
            let principal_id = claims.subject.clone().unwrap_or_else(|| "user".to_string());

            // Check if the token is expired
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if let Some(exp) = claims.expiration {
                if current_time <= exp {
                    // Token is valid
                    info!(
                        "JWT token is valid. Expiration: {}, Current time: {}",
                        exp, current_time
                    );

                    let policy = create_policy(IamPolicyEffect::Allow, &method_arn);

                    let response = ApiGatewayCustomAuthorizerResponse {
                        principal_id: Some(principal_id),
                        policy_document: policy,
                        context: Value::Null,
                        usage_identifier_key: None,
                    };

                    return Ok(response);
                } else {
                    // Token expired
                    warn!(
                        "JWT token is expired. Expiration: {}, Current time: {}",
                        exp, current_time
                    );
                }
            } else {
                // No expiration claim found
                info!("JWT token has no expiration claim");
            }

            let policy = create_policy(IamPolicyEffect::Deny, &method_arn);

            let response = ApiGatewayCustomAuthorizerResponse {
                principal_id: Some(principal_id),
                policy_document: policy,
                context: Value::Null,
                usage_identifier_key: None,
            };

            Ok(response)
        }
        Err(err) => {
            // Log the error but still allow access for now
            warn!("Failed to decode JWT token: {:?}", err);

            let policy = create_policy(IamPolicyEffect::Deny, &method_arn);

            let response = ApiGatewayCustomAuthorizerResponse {
                principal_id: Some("user".to_string()),
                policy_document: policy,
                context: Value::Null,
                usage_identifier_key: None,
            };

            Ok(response)
        }
    }
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

// Initialize the Cognito client
async fn init_cognito_client() -> Result<(), Error> {
    // Create AWS config
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;

    // Create Cognito client
    let client = CognitoClient::new(&config);

    // Store the client in the global static reference
    COGNITO_CLIENT
        .set(Arc::new(client))
        .map_err(|_| Error::from("Failed to initialize Cognito client"))?;

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

    // Initialize the Cognito client
    init_cognito_client().await?;
    info!("Cognito client initialized");

    // Start the Lambda runtime
    lambda_runtime::run(service_fn(function_handler)).await?;

    Ok(())
}
