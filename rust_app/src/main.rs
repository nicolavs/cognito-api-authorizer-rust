use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse,
};
use aws_lambda_events::event::iam::{IamPolicyEffect, IamPolicyStatement};
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::Value;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

// Export the function handler for testing
pub async fn function_handler(
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse, Error> {
    let (request, _context) = event.into_parts();

    // Log the entire request for debugging
    info!("Received authorizer request: {:?}", request);

    // Extract the authorization token from headers
    let _auth_token = if let Some(auth_header) = request
        .headers
        .get("Authorization")
        .or_else(|| request.headers.get("authorization"))
    {
        info!("Authorization header: {:?}", auth_header);
        auth_header.to_str().unwrap_or("").to_string()
    } else {
        info!("No authorization token found");
        "".to_string()
    };

    // For now, return a simple allow policy
    // In a real implementation; you would validate the token here
    let policy = ApiGatewayCustomAuthorizerPolicy {
        version: Some("2012-10-17".to_string()),
        statement: vec![IamPolicyStatement {
            action: vec!["execute-api:Invoke".to_string()],
            effect: IamPolicyEffect::Allow,
            resource: vec![request.method_arn.clone().unwrap_or_else(|| "".to_string())],
            ..Default::default()
        }],
    };

    let response = ApiGatewayCustomAuthorizerResponse {
        principal_id: Some("user".to_string()),
        policy_document: policy,
        context: Value::Null,
        usage_identifier_key: None,
    };

    Ok(response)
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

    // Start the Lambda runtime
    lambda_runtime::run(service_fn(function_handler)).await?;

    Ok(())
}
