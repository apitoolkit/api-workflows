use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestConfig {
    pub url: String,
    pub method: String,
    pub headers: Option<Vec<Header>>,
    pub body: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug)]
pub struct RequestResult {
    pub status_code: u16,
    pub body: String,
}

pub async fn base_request(
    test: &RequestConfig,
) -> Result<RequestResult, Box<dyn std::error::Error>> {
    let client = Client::new();

    let request_builder = match test.method.as_str() {
        "GET" => client.get(&test.url),
        "POST" => client.post(&test.url),
        "PUT" => client.put(&test.url),
        "DELETE" => client.delete(&test.url),
        _ => panic!("Unsupported HTTP method"),
    };

    let mut request_builder = if let Some(headers) = &test.headers {
        let mut request_builder = request_builder;
        for header in headers {
            request_builder = request_builder.header(&header.name, &header.value);
        }
        request_builder
    } else {
        request_builder
    };

    let response = request_builder.send().await?;
    let status_code = response.status().as_u16();
    let body = response.text().await?;

    Ok(RequestResult { status_code, body })
}
