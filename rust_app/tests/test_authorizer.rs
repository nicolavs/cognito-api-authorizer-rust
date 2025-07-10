use std::fs;
use std::path::Path;

use aws_lambda_events::apigw::ApiGatewayCustomAuthorizerRequestTypeRequest;
use lambda_runtime::{Context, Error, LambdaEvent};
use serde_json::Value;

// Import the function_handler from the main crate
use cognito_api_authorizer_rust::function_handler;

#[tokio::test]
async fn test_authorizer_with_event_json() -> Result<(), Error> {
    // Load the test event from the file
    let event_path = Path::new("../events/authorizer-event.json");
    println!(
        "Looking for event file at: {:?}",
        event_path
            .canonicalize()
            .unwrap_or_else(|_| Path::new("not found").to_path_buf())
    );
    let event_json =
        fs::read_to_string(event_path).expect("Should have been able to read the event file");

    // Parse the JSON into a Value
    let mut event_value: Value =
        serde_json::from_str(&event_json).expect("Should have been able to parse the event JSON");

    // Convert field names from camelCase to snake_case for Rust struct compatibility
    if let Some(obj) = event_value.as_object_mut() {
        if obj.contains_key("type") {
            let type_value = obj.remove("type").unwrap();
            obj.insert("type_".to_string(), type_value);
        }
        if obj.contains_key("methodArn") {
            let arn_value = obj.remove("methodArn").unwrap();
            obj.insert("method_arn".to_string(), arn_value);
        }
        // Add Authorization header for testing
        if let Some(headers) = obj.get_mut("headers").and_then(Value::as_object_mut) {
            headers.insert(
                "Authorization".to_string(),
                Value::String("Bearer test-token".to_string()),
            );
        }
    }

    // Convert the Value to the expected request type
    let request: ApiGatewayCustomAuthorizerRequestTypeRequest = serde_json::from_value(event_value)
        .expect("Should have been able to convert to ApiGatewayCustomAuthorizerRequestTypeRequest");

    // Create a mock context
    let context = Context::default();

    // Create a LambdaEvent
    let lambda_event = LambdaEvent::new(request, context);

    // Call the function handler
    let response = function_handler(lambda_event).await?;

    // Verify the response
    assert!(
        response.principal_id.is_some(),
        "Principal ID should be set"
    );
    assert_eq!(
        response.principal_id.unwrap(),
        "user",
        "Principal ID should be 'user'"
    );

    // Verify policy allows access
    let statement = &response.policy_document.statement[0];
    assert_eq!(
        statement.effect,
        aws_lambda_events::event::iam::IamPolicyEffect::Allow
    );

    println!("Test passed successfully!");
    Ok(())
}
