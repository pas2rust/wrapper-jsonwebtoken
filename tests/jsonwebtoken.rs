use serde_json::json;
use wrapper_jsonwebtoken::wrapper::{JsonwebtokenTrait, WrapperJWT};

#[test]
fn test_hs256_decode() {
    let mut wrapper_jwt = WrapperJWT::new(
        String::from("your_token"),
        String::from("your_secret"),
        Some(json!({"key": "value"})),
        1000 * 60 * 60,
    );
    let token = wrapper_jwt.hs256_encode().unwrap();
    wrapper_jwt.set_token(token);
    let result = wrapper_jwt.hs256_decode();
    assert!(result.is_ok());
}

#[test]
fn test_hs384_decode() {
    let mut wrapper_jwt = WrapperJWT::new(
        String::from("your_token"),
        String::from("your_secret"),
        Some(json!({"key": "value"})),
        1000 * 60 * 60,
    );
    let token = wrapper_jwt.hs384_encode().unwrap();
    wrapper_jwt.set_token(token);
    let result = wrapper_jwt.hs384_decode();
    assert!(result.is_ok());
}

#[test]
fn test_hs512_decode() {
    let mut wrapper_jwt = WrapperJWT::new(
        String::from("your_token"),
        String::from("your_secret"),
        Some(json!({"key": "value"})),
        1000 * 60 * 60,
    );
    let token = wrapper_jwt.hs512_encode().unwrap();
    wrapper_jwt.set_token(token);
    let result = wrapper_jwt.hs512_decode();
    assert!(result.is_ok());
}

#[test]
fn test_hs256_encode() {
    let wrapper_jwt = WrapperJWT::new(
        String::from("your_token"),
        String::from("your_secret"),
        Some(json!({"key": "value"})),
        1000 * 60 * 60,
    );
    let result = wrapper_jwt.hs256_encode();
    assert!(result.is_ok());
}

#[test]
fn test_hs384_encode() {
    let wrapper_jwt = WrapperJWT::new(
        String::from("your_token"),
        String::from("your_secret"),
        Some(json!({"key": "value"})),
        1000 * 60 * 60,
    );
    let result = wrapper_jwt.hs384_encode();
    assert!(result.is_ok());
}

#[test]
fn test_hs512_encode() {
    let wrapper_jwt = WrapperJWT::new(
        String::from("your_token"),
        String::from("your_secret"),
        Some(json!({"key": "value"})),
        1000 * 60 * 60,
    );
    let result = wrapper_jwt.hs512_encode();
    assert!(result.is_ok());
}
