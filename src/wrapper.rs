use chrono::Utc;
use darth_rust::DarthRust;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, PartialEq, Debug, DarthRust, Clone)]
pub struct Token {
    pub items: Value,
    pub exp: usize,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, DarthRust, Clone)]
pub struct WrapperJWT {
    pub token: String,
    pub secret: String,
    pub items: Option<Value>,
    pub exp: usize,
}

pub trait JsonwebtokenTrait {
    fn hs256_decode(&self) -> Result<Token, jsonwebtoken::errors::Error>;
    fn hs384_decode(&self) -> Result<Token, jsonwebtoken::errors::Error>;
    fn hs512_decode(&self) -> Result<Token, jsonwebtoken::errors::Error>;
    fn hs256_encode(&self) -> Result<String, jsonwebtoken::errors::Error>;
    fn hs384_encode(&self) -> Result<String, jsonwebtoken::errors::Error>;
    fn hs512_encode(&self) -> Result<String, jsonwebtoken::errors::Error>;
}

impl JsonwebtokenTrait for WrapperJWT {
    fn hs256_decode(&self) -> Result<Token, jsonwebtoken::errors::Error> {
        let token = &self.token;
        let secret = &self.secret;
        let res = decode::<Token>(
            &token,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::new(jsonwebtoken::Algorithm::HS256),
        )?;
        Ok(res.claims)
    }
    fn hs384_decode(&self) -> Result<Token, jsonwebtoken::errors::Error> {
        let token = &self.token;
        let secret = &self.secret;
        let res = decode::<Token>(
            &token,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::new(jsonwebtoken::Algorithm::HS384),
        )?;
        Ok(res.claims)
    }
    fn hs512_decode(&self) -> Result<Token, jsonwebtoken::errors::Error> {
        let token = &self.token;
        let secret = &self.secret;
        let res = decode::<Token>(
            &token,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::new(jsonwebtoken::Algorithm::HS512),
        )?;
        Ok(res.claims)
    }
    fn hs256_encode(&self) -> Result<String, jsonwebtoken::errors::Error> {
        let secret = &self.secret;
        let exp = &self.exp;
        let items = self.items.as_ref().expect("items must be provided");
        let now = Utc::now().timestamp() as usize;
        let exp = now + exp;
        let my_claims = Token::new(items.clone(), exp);
        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        encode(&header, &my_claims, &EncodingKey::from_secret(secret.as_ref()))
    }
    fn hs384_encode(&self) -> Result<String, jsonwebtoken::errors::Error> {
        let secret = &self.secret;
        let exp = &self.exp;
        let items = self.items.as_ref().expect("items must be provided");
        let now = Utc::now().timestamp() as usize;
        let exp = now + exp;
        let my_claims = Token::new(items.clone(), exp);
        let header = Header::new(jsonwebtoken::Algorithm::HS384);
        encode(&header, &my_claims, &EncodingKey::from_secret(secret.as_ref()))
    }
    fn hs512_encode(&self) -> Result<String, jsonwebtoken::errors::Error> {
        let secret = &self.secret;
        let exp = &self.exp;
        let items = self.items.as_ref().expect("items must be provided");
        let now = Utc::now().timestamp() as usize;
        let exp = now + exp;
        let my_claims = Token::new(items.clone(), exp);
        let header = Header::new(jsonwebtoken::Algorithm::HS512);
        encode(&header, &my_claims, &EncodingKey::from_secret(secret.as_ref()))
    }
}
