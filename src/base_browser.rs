use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use thirtyfour::prelude::*;
use thirtyfour::DesiredCapabilities;


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

    let mut driver = None;

    // Find the metadata to configure the browser
    for (i, item) in test_cases.iter().enumerate() {
        if let Some(metadata) = &item.metadata {
            log::debug!("running on : {:?}", metadata.browser);
    
            driver = match &metadata.browser {
                Some(browser_str) => {
                    let caps = match browser_str.as_str() {
                        "firefox" => {
                            println!("Initializing Firefox");
                            let mut caps = DesiredCapabilities::firefox();
                            if metadata.headless.unwrap_or(false) {
                                caps.set_headless()?;
                            }
                            caps
                        },
                        _ => {
                            println!("Unrecognized browser '{}', defaulting to Firefox", browser_str);
                            let mut caps = DesiredCapabilities::firefox();
                            if metadata.headless.unwrap_or(false) {
                                caps.set_headless()?;
                            }
                            caps
                        }
                    };
    
                    Some(WebDriver::new("http://localhost:4444", caps).await?)
                },
                None => {
                    println!("No browser specified, defaulting to Firefox");
                    let mut caps = DesiredCapabilities::firefox();
                    if metadata.headless.unwrap_or(false) {
                        caps.set_headless()?;
                    }
                    Some(WebDriver::new("http://localhost:4444", caps).await?)
                }
            };
    
            break;
        }
    }
    
    if driver.is_none() {
        log::debug!("No driver configuration found in metadata");
    }
    
    let driver = driver.unwrap();


    let mut all_results = Vec::new();

    for test_case in test_cases {

        let result = base_browser(test_case, driver.clone()).await;
        match result {
            Ok(mut res) => {
                if should_log {
                    log::debug!("Test passed: {:?}", res);
                }
                all_results.append(&mut res);
            }
            Err(err) => {
                if should_log {
                    log::error!(target: "testkit", "{}", err);
                }
                return Err(err);
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
        println!("Running group: {:?}", group.group);

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