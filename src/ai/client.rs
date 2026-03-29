use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Bankr LLM Gateway — Anthropic-compatible endpoint
// Base URL: https://llm.bankr.bot
// Auth:     X-API-Key: bk_YOUR_KEY
// Format:   POST /v1/messages  (identical to Anthropic Messages API)
// ---------------------------------------------------------------------------

const BANKR_BASE_URL: &str = "https://llm.bankr.bot";
const DEFAULT_MODEL: &str = "claude-haiku-4.5";
const MAX_TOKENS: u32 = 2048;

#[derive(Debug, Serialize)]
pub struct Message {
    pub role: &'static str,
    pub content: String,
}

#[derive(Debug, Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<Message>,
}

#[derive(Debug, Deserialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MessagesResponse {
    pub content: Vec<ContentBlock>,
}

pub struct BankrClient {
    api_key: String,
    model: String,
    base_url: String,
}

impl BankrClient {
    /// Create a new client. Reads BANKR_API_KEY from env if api_key is None.
    pub fn new(api_key: Option<String>, model: Option<String>) -> Result<Self> {
        let key = api_key
            .or_else(|| std::env::var("BANKR_API_KEY").ok())
            .context(
                "Bankr API key not found.\n  Set BANKR_API_KEY env var or pass --api-key bk_YOUR_KEY\n  Get a key at: https://bankr.bot/api",
            )?;

        Ok(Self {
            api_key: key,
            model: model.unwrap_or_else(|| DEFAULT_MODEL.to_string()),
            base_url: std::env::var("BANKR_BASE_URL")
                .unwrap_or_else(|_| BANKR_BASE_URL.to_string()),
        })
    }

    /// Send a single-turn request and return the text response.
    pub fn complete(&self, system: &str, user: &str) -> Result<String> {
        let url = format!("{}/v1/messages", self.base_url);

        let body = MessagesRequest {
            model: &self.model,
            max_tokens: MAX_TOKENS,
            system,
            messages: vec![Message {
                role: "user",
                content: user.to_string(),
            }],
        };

        let body_json = serde_json::to_string(&body)?;

        let response = minreq::post(&url)
            .with_header("Content-Type", "application/json")
            .with_header("X-API-Key", &self.api_key)
            .with_body(body_json)
            .with_timeout(60)
            .send()
            .map_err(|e| anyhow::anyhow!("Network error calling Bankr LLM Gateway: {}", e))?;

        let status = response.status_code;
        let text = response
            .as_str()
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in response: {}", e))?;

        if status != 200 {
            bail!("Bankr LLM Gateway error {}: {}", status, text);
        }

        let parsed: MessagesResponse = serde_json::from_str(text)
            .context("Failed to parse Bankr LLM Gateway response")?;

        let content = parsed
            .content
            .into_iter()
            .find(|b| b.block_type == "text")
            .and_then(|b| b.text)
            .unwrap_or_default();

        Ok(content)
    }

    pub fn model(&self) -> &str {
        &self.model
    }
}
