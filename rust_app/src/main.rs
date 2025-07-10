use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

// Define the structure for API Gateway authorizer request
#[derive(Deserialize, Debug)]
struct ApiGatewayAuthorizerRequest {
    #[serde(rename = "type")]
    auth_type: Option<String>,
    methodArn: String,
    authorizationToken: Option<String>,
    // Include headers for REQUEST type authorizers
    headers: Option<std::collections::HashMap<String, String>>,
}

// Define the response structure
#[derive(Serialize, Debug)]
struct ApiGatewayAuthorizerResponse {
    principalId: String,
    policyDocument: PolicyDocument,
}

#[derive(Serialize, Debug)]
struct PolicyDocument {
    Version: String,
    Statement: Vec<Statement>,
}

#[derive(Serialize, Debug)]
struct Statement {
    Action: String,
    Effect: String,
    Resource: String,
}

async fn function_handler(event: LambdaEvent<ApiGatewayAuthorizerRequest>) -> Result<ApiGatewayAuthorizerResponse, Error> {
    let (request, _context) = event.into_parts();
    
    // Log the entire request for debugging
    info!("Received authorizer request: {:?}", request);
    
    // Extract the authorization token
    let auth_token = match &request.authorizationToken {
        Some(token) => {
            info!("Authorization token: {}", token);
            token.clone()
        },
        None => {
            // If no token in authorizationToken, try to get from headers
            if let Some(headers) = &request.headers {
                if let Some(auth_header) = headers.get("Authorization").or_else(|| headers.get("authorization")) {
                    info!("Authorization header: {}", auth_header);
                    auth_header.clone()
                } else {
                    info!("No Authorization header found");
                    "".to_string()
                }
            } else {
                info!("No headers and no authorization token found");
                "".to_string()
            }
        }
    };
    
    // For now, just return a simple allow policy
    // In a real implementation, you would validate the token here
    let response = ApiGatewayAuthorizerResponse {
        principalId: "user".to_string(),
        policyDocument: PolicyDocument {
            Version: "2012-10-17".to_string(),
            Statement: vec![
                Statement {
                    Action: "execute-api:Invoke".to_string(),
                    Effect: "Allow".to_string(),
                    Resource: request.methodArn,
                }
            ],
        },
    };
    
    Ok(response)
}

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