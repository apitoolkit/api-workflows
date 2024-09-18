use std::io::{self, Write};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use thirtyfour::prelude::*;
use thirtyfour::{
    ChromeCapabilities, DesiredCapabilities, EdgeCapabilities, FirefoxCapabilities,
    SafariCapabilities,
};

enum BrowserCapabilities {
    Firefox(FirefoxCapabilities),
    Chrome(ChromeCapabilities),
    Safari(SafariCapabilities),
    Edge(EdgeCapabilities),
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TestStep {
    visit: Option<String>,
    find: Option<String>,
    find_xpath: Option<String>,
    #[serde(default)]
    type_text: Option<String>,
    #[serde(default)]
    click: Option<bool>,
    #[serde(default)]
    wait: Option<u64>,
    assert: Option<Vec<Assertion>>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Assertion {
    array: Option<String>,
    array_xpath: Option<String>,
    empty: Option<String>,
    empty_xpath: Option<String>,
    string: Option<String>,
    string_xpath: Option<String>,
    equal: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestItem {
    metadata: Option<Metadata>,
    groups: Vec<Group>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    name: Option<String>,
    description: Option<String>,
    headless: Option<bool>,
    browser: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Group {
    group: String,
    steps: Vec<TestStep>,
}

#[derive(Debug, Default, Serialize)]
pub struct RequestResult {
    pub step_name: Option<String>,
    pub step_index: u32,
}
pub async fn run_browser(
    test_cases: &Vec<TestItem>,
    should_log: bool,
) -> Result<Vec<RequestResult>, Box<dyn std::error::Error>> {
    let mut driver: Option<WebDriver> = None;

    // Find the metadata to configure the browser
    for (i, item) in test_cases.iter().enumerate() {
        if let Some(metadata) = &item.metadata {
            log::info!(target: "testkit", "running on:{:?}", metadata.browser.as_ref().unwrap());

            driver = get_web_driver(metadata).await;
            break;
        }
    }

    let mut all_results = Vec::new();

    if driver.is_none() {
        log::info!(target:"testkit", "no driver configuration found in metadata");
    } else {
        for test_case in test_cases {
            let result = base_browser(test_case, driver.clone().unwrap()).await;
            match result {
                Ok(mut res) => {
                    if should_log {
                        log::info!(target:"testkit", "test passed:{:?}", res);
                    }
                    all_results.append(&mut res);
                }
                Err(err) => {
                    if should_log {
                        log::error!(target:"testkit", "{:?}", err);
                    }
                    return Err(err);
                }
            }
        }
    }

    Ok(all_results)
}

pub async fn base_browser(
    test_item: &TestItem,
    client: WebDriver,
) -> Result<Vec<RequestResult>, Box<dyn std::error::Error>> {
    let mut results: Vec<RequestResult> = Vec::new();
    for (i, group) in test_item.groups.iter().enumerate() {
        for (j, step) in group.steps.iter().enumerate() {
            if let Some(url) = &step.visit {
                client.get(url).await?;
            }
            if let Some(selector) = &step.find {
                let element = client.find(By::Css(selector)).await?;
                if step.click.unwrap_or(false) {
                    element.click().await?;
                }
                if let Some(text) = &step.type_text {
                    element.send_keys(text).await?;
                }
            }
            if let Some(xpath) = &step.find_xpath {
                let element = client.find(By::XPath(xpath)).await?;
                if step.click.unwrap_or(false) {
                    element.click().await?;
                }
                if let Some(text) = &step.type_text {
                    element.send_keys(text).await?;
                }
            }
            if let Some(wait_time) = step.wait {
                tokio::time::sleep(Duration::from_millis(wait_time)).await;
            }

            results.push(RequestResult {
                step_name: Some(format!("{} - step {}", group.group, j)),
                step_index: i as u32,
            });
        }
    }

    client.quit().await?;
    Ok(results)
}

async fn get_web_driver(metadata: &Metadata) -> Option<WebDriver> {
    let port = "http://localhost:4444";
    match metadata.browser {
        Some(ref browser_str) => {
            let caps: Option<BrowserCapabilities> = match browser_str.as_str() {
                "firefox" => {
                    log::info!(target: "testkit", "initializing Firefox");
                    let mut caps = DesiredCapabilities::firefox();
                    if metadata.headless.unwrap_or(false) {
                        caps.set_headless().unwrap();
                    }
                    Some(BrowserCapabilities::Firefox(caps))
                }
                "chrome" => {
                    log::info!(target: "testkit", "initializing Chrome");
                    let mut caps = DesiredCapabilities::chrome();
                    if metadata.headless.unwrap_or(false) {
                        caps.set_headless().unwrap();
                    }
                    Some(BrowserCapabilities::Chrome(caps))
                }
                "safari" => {
                    log::info!(target: "testkit", "initializing Safari");
                    let mut user_prompt = None;
                    if metadata.headless.unwrap_or(false) {
                        // Reference: https://github.com/SeleniumHQ/selenium/issues/5985
                        log::error!(target: "testkit", "safari driver has no headless mode support");
                        user_prompt =
                            prompt_user("Do you want to continue without headless mode? (y/n) ")
                    }
                    match user_prompt {
                        Some('n') | Some('N') => None,
                        _ => Some(BrowserCapabilities::Safari(DesiredCapabilities::safari())),
                    }
                }
                "edge" => {
                    log::info!(target: "testkit", "initializing Edge");
                    let mut caps = DesiredCapabilities::edge();
                    if metadata.headless.unwrap_or(false) {
                        caps.set_headless().unwrap();
                    }
                    Some(BrowserCapabilities::Edge(caps))
                }
                _ => {
                    log::info!(target: "testkit",
                        "unrecognized browser '{}', defaulting to Firefox",
                        browser_str
                    );
                    let mut caps = DesiredCapabilities::firefox();
                    if metadata.headless.unwrap_or(false) {
                        caps.set_headless().unwrap();
                    }
                    Some(BrowserCapabilities::Firefox(caps))
                }
            };

            match caps {
                Some(BrowserCapabilities::Chrome(chrome_caps)) => {
                    Some(WebDriver::new(port, chrome_caps).await.unwrap())
                }
                Some(BrowserCapabilities::Firefox(firefox_caps)) => {
                    Some(WebDriver::new(port, firefox_caps).await.unwrap())
                }
                Some(BrowserCapabilities::Safari(safari_caps)) => {
                    Some(WebDriver::new(port, safari_caps).await.unwrap())
                }
                Some(BrowserCapabilities::Edge(edge_caps)) => {
                    Some(WebDriver::new(port, edge_caps).await.unwrap())
                }
                _ => None,
            }
        }
        None => {
            log::info!("No browser specified, defaulting to Firefox");
            let mut firefox_caps = DesiredCapabilities::firefox();
            if metadata.headless.unwrap_or(false) {
                firefox_caps.set_headless().unwrap();
            }
            Some(WebDriver::new(port, firefox_caps).await.unwrap())
        }
    }
}

fn prompt_user(prompt: &str) -> Option<char> {
    log::info!("{}", prompt);
    io::stdout().flush().expect("Failed to flush stdout");

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        input.chars().next()
    } else {
        None
    }
}
