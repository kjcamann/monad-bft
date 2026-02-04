use axum::http::HeaderValue;
use reqwest::Client;
use serde_json::{Value, json};
use std::sync::Arc;

const CLAUDE_API_KEY: &'static str = std::env!("PIQL_CLAUDE_KEY");

#[derive(Clone)]
pub struct ClaudeClient {
    client: Client,
    api_key: Arc<String>,
}

impl ClaudeClient {
    pub fn new() -> Self {
        let api_key = CLAUDE_API_KEY.to_string();

        Self {
            client: Client::new(),
            api_key: Arc::new(api_key),
        }
    }

    pub async fn generate_piql(
        &self,
        system_prompt: &str,
        user_request: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", HeaderValue::from_str(&self.api_key).unwrap())
            .header("anthropic-version", HeaderValue::from_static("2023-06-01"))
            .json(&serde_json::json!({
                // Use the Haiku model here
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 300,
                "temperature": 0.0,
                "system": system_prompt,
                "messages": [
                    {
                        "role": "user",
                        "content": user_request
                    }
                ]
            }))
            .send()
            .await?;

        let body: Value = response.json().await?;

        eprintln!("{body:#?}");

        let piql = body["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();

        Ok(piql)
    }
}
