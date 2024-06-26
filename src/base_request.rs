use chrono::{NaiveDate, NaiveDateTime};
use jsonpath_lib::select;
use miette::{Diagnostic, GraphicalReportHandler, GraphicalTheme, NamedSource, Report, SourceSpan};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use rhai::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::serde_as;
use std::{collections::HashMap, env, env::VarError};
use thiserror::Error;

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct TestItem {
    title: Option<String>,
    dump: Option<bool>,
    #[serde(flatten)]
    request: RequestConfig,
    #[serde(default)]
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    asserts: Option<Vec<Assert>>,
    exports: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Assert {
    #[serde(rename = "ok")]
    IsOk(String),
    #[serde(rename = "array")]
    IsArray(String),
    #[serde(rename = "empty")]
    IsEmpty(String),
    #[serde(rename = "string")]
    IsString(String),
    #[serde(rename = "number")]
    IsNumber(String),
    #[serde(rename = "boolean")]
    IsBoolean(String),
    #[serde(rename = "null")]
    IsNull(String),
    #[serde(rename = "exists")]
    Exists(String),
    #[serde[rename = "date"]]
    IsDate(String),
    #[serde[rename = "notEmpty"]]
    NotEmpty(String), // Add other assertion types as needed
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RequestConfig {
    #[serde(flatten)]
    pub http_method: HttpMethod,
    pub headers: Option<HashMap<String, String>>,
    pub json: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    GET(String),
    POST(String),
    DELETE(String),
    PUT(String), // Add other HTTP methods as needed
}

impl Default for HttpMethod {
    fn default() -> Self {
        HttpMethod::GET("<UNSET>".into())
    }
}

#[derive(Debug, Default, Serialize)]
pub struct RequestResult {
    pub step_name: Option<String>,
    pub step_index: u32,
    pub assert_results: Vec<Result<bool, AssertionError>>,
    pub request: RequestAndResponse,
    pub step_log: String,
    pub step_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequestAndResponse {
    req: RequestConfig,
    resp: ResponseObject,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseObject {
    status: u16,
    headers: Value,
    json: Value,
    raw: String,
}

#[derive(Error, Serialize, Clone, Debug, Diagnostic)]
#[error("request assertion failed!")]
#[diagnostic(
    // code(asertion),
    severity(error)
    // help("try doing it better next time?")
)]
pub struct AssertionError {
    #[help]
    advice: Option<String>,
    #[source_code]
    #[serde(skip_serializing)]
    src: NamedSource<String>,
    #[label("This jsonpath here")]
    #[serde(skip_serializing)]
    bad_bit: SourceSpan,
}

fn report_error(diag: Report) -> String {
    let mut out = String::new();
    GraphicalReportHandler::new_themed(GraphicalTheme::unicode())
        .with_width(80)
        .render_report(&mut out, diag.as_ref())
        .unwrap();
    out
}

#[derive(Default, Clone)]
pub struct TestContext {
    pub plan: Option<String>,
    pub step: Option<String>,
    pub step_index: u32,
    pub path: String,
    pub file: String,
    pub file_source: String,
    pub should_log: bool,
}

pub async fn run(
    ctx: TestContext,
    exec_string: String,
    should_log: bool,
) -> Result<Vec<RequestResult>, Box<dyn std::error::Error>> {
    let test_items: Vec<TestItem> = serde_yaml::from_str(&exec_string)?;

    log::debug!(target:"testkit","test_items: {:#?}", test_items);

    let result = base_request(ctx.clone(), &test_items, should_log, None).await;
    match result {
        Ok(res) => {
            if should_log {
                log::debug!("Test passed: {:?}", res);
            }
            Ok(res)
        }
        Err(err) => {
            if should_log {
                log::error!(target:"testkit","{}", err);
            }
            Err(err)
        }
    }
}

pub async fn run_json(
    ctx: TestContext,
    exec_string: String,
    col_id: Option<String>,
) -> Result<Vec<RequestResult>, Box<dyn std::error::Error>> {
    println!("{}", &exec_string);
    let test_items: Vec<TestItem> = serde_json::from_str(&exec_string)?;
    log::debug!(target:"testkit","test_items: {:#?}", test_items);
    let should_log = ctx.should_log;
    let result = base_request(ctx.clone(), &test_items, should_log, col_id).await;
    match result {
        Ok(res) => {
            if should_log {
                log::debug!("Test passed: {:?}", res);
            }
            Ok(res)
        }
        Err(err) => {
            if should_log {
                log::error!(target:"testkit","{}", err);
            }
            Err(err)
        }
    }
}

// base_request would process a test plan, logging status updates as they happen.
// Logging in place allows tracking of the results earliers
pub async fn base_request(
    ctx: TestContext,
    test_items: &Vec<TestItem>,
    should_log: bool,
    col_id: Option<String>,
) -> Result<Vec<RequestResult>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .connection_verbose(true)
        .build()?;
    let mut results: Vec<RequestResult> = Vec::new();
    let mut exports_map: HashMap<String, Value> = HashMap::new();

    for (i, test_item) in test_items.iter().enumerate() {
        let mut ctx = ctx.clone();
        let mut step_result = RequestResult {
            step_name: test_item.title.clone(),
            step_index: i as u32,
            ..Default::default()
        };
        ctx.step = test_item.title.clone();
        ctx.step_index = i as u32;
        let request_line = format!(
            "{:?} ⬅ {}/{}",
            test_item.request.http_method,
            ctx.plan.clone().unwrap_or("_plan".into()),
            ctx.step.clone().unwrap_or(ctx.step_index.to_string())
        );
        step_result.step_log.push_str(&request_line);
        step_result.step_log.push_str("\n");
        if should_log {
            log::info!(target:"testkit", "");
            log::info!(target:"testkit", "{}", request_line.to_string());
        }
        let mut request_builder = match &test_item.request.http_method {
            HttpMethod::GET(url) => client.get(format_url(&ctx, url, &exports_map)),
            HttpMethod::POST(url) => client.post(format_url(&ctx, url, &exports_map)),
            HttpMethod::PUT(url) => client.put(format_url(&ctx, url, &exports_map)),
            HttpMethod::DELETE(url) => client.delete(format_url(&ctx, url, &exports_map)),
        };
        request_builder = request_builder.header("X-Testkit-Run", "true");

        if let Some(col) = &col_id {
            request_builder = request_builder.header("X-Testkit-Collection-ID", col);
        }

        if let Some(headers) = &test_item.request.headers {
            for (name, value) in headers {
                let mut value = value.clone();
                for export in get_exports_paths(&value) {
                    match get_export_variable(&export, ctx.step_index, &exports_map) {
                        Some(v) => value = value.replace(&export, &v.to_string()),
                        None => {
                            let error_message = format!("Export not found: {}", export);
                            step_result.step_log.push_str(&error_message);
                            step_result.step_log.push_str("\n");
                            if should_log {
                                log::error!(target:"testkit","{}", error_message)
                            }
                        }
                    }
                }
                for env_var in get_env_variable_paths(&value) {
                    match get_env_variable(&env_var) {
                        Ok(val) => value = value.replace(&env_var, &val),
                        Err(err) => {
                            let error_message =
                                format!("Error getting environment variable {}: {}", env_var, err);
                            step_result.step_log.push_str(&error_message);
                            step_result.step_log.push_str("\n");
                            if should_log {
                                log::error!(target:"testkit","{}", error_message)
                            }
                        }
                    }
                }

                request_builder = request_builder.header(name, value);
            }
        }

        if let Some(json) = &test_item.request.json {
            let mut j_string = json.to_string();
            for export in get_exports_paths(&j_string) {
                match get_export_variable(&export, ctx.step_index, &exports_map) {
                    Some(v) => j_string = j_string.replace(&export, &v.to_string()),
                    None => {
                        let error_message = format!("Export not found: {}", export);
                        step_result.step_log.push_str(&error_message);
                        step_result.step_log.push_str("\n");
                        if should_log {
                            log::error!(target:"testkit","{}", error_message)
                        }
                    }
                }
            }

            for env_var in get_env_variable_paths(&j_string) {
                match get_env_variable(&env_var) {
                    Ok(val) => j_string = j_string.replace(&env_var, &val),
                    Err(err) => {
                        let error_message =
                            format!("Error getting environment variable {}: {}", env_var, err);
                        step_result.step_log.push_str(&error_message);
                        step_result.step_log.push_str("\n");
                        if should_log {
                            log::error!(target:"testkit","{}", error_message)
                        }
                    }
                }
            }
            let clean_json: Value = serde_json::from_str(&j_string)?;
            request_builder = request_builder.json(&clean_json);
        }

        let mut request_config = test_item.request.clone();
        if let Some(col) = &col_id {
            let mut headers = request_config.headers.clone().unwrap_or_default();
            headers.insert("X-Testkit-Collection-ID".into(), col.clone());
            request_config.headers = Some(headers);
        }

        let response = request_builder.send().await;

        match response {
            Err(err) => {
                let error_message = format!("Error sending request: {}", err);
                step_result.step_log.push_str(&error_message);
                step_result.step_log.push_str("\n");
                if should_log {
                    log::error!(target:"testkit","{}", error_message)
                }
                step_result.step_error = Some(error_message);

                results.push(step_result);
            }
            Ok(response) => {
                let status_code = response.status().as_u16();
                let header_hashmap = header_map_to_hashmap(response.headers());

                let raw_body_res = response.text().await;
                let raw_body = raw_body_res.unwrap_or("{}".to_string());
                let json_body_res = serde_json::from_str(&raw_body);
                let json_body = json_body_res.unwrap_or(Value::Object(serde_json::Map::new()));

                let assert_object = RequestAndResponse {
                    req: request_config,
                    resp: ResponseObject {
                        status: status_code,
                        headers: serde_json::json!(header_hashmap),
                        json: json_body.clone(),
                        raw: raw_body,
                    },
                };
                step_result.request = assert_object.clone();

                let assert_context: Value = serde_json::json!(&assert_object);
                if test_item.dump.unwrap_or(false) {
                    let dump_message = format!(
                        "💡 DUMP jsonpath request response context:\n {}",
                        colored_json::to_colored_json_auto(&assert_context)
                            .unwrap_or(assert_context.to_owned().to_string())
                    );
                    step_result.step_log.push_str(&dump_message);
                    step_result.step_log.push_str("\n");
                    if should_log {
                        log::info!(target:"testkit","{}", dump_message)
                    }
                }
                let assert_results = check_assertions(
                    ctx,
                    &(test_item.asserts.clone().unwrap_or(vec![])),
                    assert_context,
                    &exports_map,
                    &mut step_result.step_log,
                )
                .await;
                // if let Some(outputs) = &step.outputs {
                //     update_outputs(outputs, &response_json);
                // }
                if let Some(exports) = &test_item.exports {
                    for (key, value) in exports.into_iter() {
                        let json_bod = &serde_json::json!(assert_object);
                        let export = select(json_bod, &value);
                        match export {
                            Ok(v) => {
                                if let Some(evaled) = v.first() {
                                    exports_map.insert(
                                        format!("{}_{}", i, key.to_string()),
                                        evaled.clone().clone(),
                                    );
                                }
                            }
                            Err(err) => {
                                let error_message = format!("Error getting export value: {}", err);
                                step_result.step_log.push_str(&error_message);
                                step_result.step_log.push_str("\n");
                                if should_log {
                                    log::error!(target:"testkit","{}", error_message)
                                }
                            }
                        }
                    }
                }
                step_result.assert_results = assert_results;
                results.push(step_result);
            }
        }
    }
    Ok(results)
}

fn header_map_to_hashmap(headers: &HeaderMap<HeaderValue>) -> HashMap<String, Vec<String>> {
    let mut header_hashmap = HashMap::new();
    for (k, v) in headers {
        let k = k.as_str().to_owned();
        let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
        header_hashmap.entry(k).or_insert_with(Vec::new).push(v)
    }
    header_hashmap
}

// Naive implementation that might not work for all jsonpaths and might need to be changed.
// Should add tests to check which jsonpaths would not be supported
fn find_all_jsonpaths(input: &String) -> Vec<&str> {
    input
        .split_whitespace()
        .filter(|x| x.starts_with("$.resp"))
        .collect()
}

fn get_var_step(input: &str, current_step: u32) -> Option<u32> {
    let start_pos = input.find('[')?;
    let end_pos = input[start_pos + 1..].find(']')? + start_pos + 1;
    let n_str = &input[start_pos + 1..end_pos];

    if let Ok(n) = n_str.parse::<i32>() {
        if n < 0 {
            let target_step = (current_step as i32) + n;
            if target_step >= 0 {
                return Some(target_step.try_into().unwrap());
            }
            None
        } else {
            Some(n.try_into().unwrap())
        }
    } else {
        None
    }
}

// Replace output variables with actual values in request url
fn format_url(
    ctx: &TestContext,
    original_url: &String,
    exports_map: &HashMap<String, Value>,
) -> String {
    let mut url = original_url.clone();
    for export in get_exports_paths(&url) {
        match get_export_variable(&export, ctx.step_index, &exports_map) {
            Some(v) => url = url.replace(&export, &v.to_string()),
            None => {
                let error_message = format!("Export not found: {}", export);
                log::error!(target:"testkit","{}", error_message)
            }
        }
    }

    for env_var in get_env_variable_paths(&original_url) {
        match get_env_variable(&env_var) {
            Ok(val) => url = url.replace(&env_var, &val),
            Err(err) => {
                let error_message =
                    format!("Error getting environment variable {}: {}", env_var, err);
                log::error!(target:"testkit","{}", error_message)
            }
        }
    }
    url
}

fn find_all_output_vars(
    input: &str,
    outputs: &HashMap<String, Value>,
    step_index: u32,
) -> HashMap<String, Option<Value>> {
    let mut val_map = HashMap::new();

    let vars: Vec<String> = input
        .split_whitespace()
        .filter(|x| x.starts_with("$.steps"))
        .map(|x| x.to_string())
        .collect();

    for var in vars {
        let target_step = get_var_step(&var, step_index).unwrap_or_default();
        let elements: Vec<&str> = var.split('.').collect();
        let target_key = elements.last().unwrap_or(&"");
        let output_key = format!("{}_{}", target_step, target_key);
        val_map.insert(var, outputs.get(&output_key).cloned());
    }
    val_map
}

fn get_exports_paths(val: &String) -> Vec<String> {
    let regex_pattern = r#"\$\.steps\[(-?\d+)\]\.([a-zA-Z0-9]+)"#;
    let regex = Regex::new(regex_pattern).unwrap();
    let exports: Vec<String> = regex
        .find_iter(&val)
        .map(|v| v.as_str().to_string())
        .collect();
    exports
}

fn get_env_variable_paths(val: &String) -> Vec<String> {
    let regex_pattern = r#"\$\.(env\.[A-Za-z_][A-Za-z0-9_]*)"#;
    let regex = Regex::new(regex_pattern).unwrap();
    let env_vars: Vec<String> = regex
        .find_iter(&val)
        .map(|v| v.as_str().to_string())
        .collect();
    env_vars
}

fn get_env_variable(env_key_path: &String) -> Result<String, VarError> {
    let key = env_key_path.split(".").last().unwrap_or_default();
    env::var(key)
}

fn get_export_variable<'a>(
    export_path: &String,
    current_step: u32,
    exports_map: &'a HashMap<String, Value>,
) -> Option<&'a Value> {
    let target_step = get_var_step(&export_path, current_step).unwrap_or_default();
    let elements: Vec<&str> = export_path.split('.').collect();
    let target_key = elements.last().unwrap_or(&"");
    let export_key = format!("{}_{}", target_step, target_key);
    exports_map.get(&export_key)
}
// 1. First we extract a list of jsonpaths
// 2. Build a json with all the fields which can be referenced via jsonpath
// 3. Apply the jsonpaths over this json and save their values to a map
// 4. replace the jsonpaths with that value in the original expr string
// 5. Evaluate the expression with the expressions library.
// TODO: decide on both error handling and the reporting approach
fn evaluate_expressions<'a, T: Clone + 'static>(
    ctx: TestContext,
    original_expr: &String,
    object: &'a Value,
    outputs: &HashMap<String, Value>,
) -> Result<(T, String), AssertionError> {
    let paths = find_all_jsonpaths(&original_expr);
    let output_vars = find_all_output_vars(&original_expr, outputs, ctx.step_index);
    let mut expr = original_expr.clone();

    for (var_path, var_value) in output_vars.iter() {
        if let Some(value) = var_value {
            expr = expr.replace(var_path, value.to_string().as_str());
        } else {
            return Err(AssertionError {
                advice: Some(format!(
                    "{}: could not resolve output variable path to any real value",
                    var_path
                )),
                src: NamedSource::new(ctx.file, var_path.clone()),
                bad_bit: (0, var_path.len()).into(),
            });
        }
    }

    for env_var in get_env_variable_paths(&original_expr) {
        match get_env_variable(&env_var) {
            Ok(val) => expr = expr.replace(&env_var, &val),
            Err(err) => {
                let error_message =
                    format!("Error getting environment variable {}: {}", env_var, err);
                log::error!(target:"testkit","{}", error_message)
            }
        }
    }

    for path in paths {
        match select(&object, &path) {
            Ok(selected_value) => {
                if let Some(selected_value) = selected_value.first() {
                    expr = expr.replace(path, &selected_value.to_string());
                } else {
                    let i = original_expr.find(path).unwrap_or(0);
                    // TODO: reproduce and improve this error
                    return Err(AssertionError {
                        advice: Some(
                            "The given json path could not be located in the json body".to_string(),
                        ),
                        src: NamedSource::new(ctx.file, original_expr.clone()),
                        bad_bit: (i, i + path.len()).into(),
                    });
                }
            }
            Err(_err) => {
                // TODO: reproduce and improve this error. Use the _err argument
                // The given jsonpath could not be evaluated to a value
                return Err(AssertionError {
                    advice: Some(
                        "could not resolve jsonpaths to any real value in the json object"
                            .to_string(),
                    ),
                    src: NamedSource::new(ctx.file, expr),
                    bad_bit: (0, 4).into(),
                });
            }
        }
    }

    log::debug!(target:"testkit","normalized pre-evaluation assert expression: {:?}", &expr);
    // TODO: reproduce and improve this error
    let evaluated = parse_expression::<T>(&expr.clone()).map_err(|_e| AssertionError {
        advice: Some("Comparison expression could not be evaluated".to_string()),
        src: NamedSource::new(ctx.file, expr.clone()),
        bad_bit: (0, 4).into(),
    })?;
    Ok((evaluated, expr.clone()))
}

fn evaluate_value<'a, T: Clone + 'static>(
    ctx: TestContext,
    expr: &'a String,
    object: &'a Value,
    value_type: &str,
) -> Result<(bool, String), AssertionError> {
    let mut path = expr.clone();
    let mut format = String::new();
    let should_log = ctx.should_log;
    if value_type == "date" {
        let elements: Vec<&str> = expr.split_whitespace().collect();
        if elements.len() < 2 {
            return Err(AssertionError {
                advice: Some("date format is required".to_string()),
                src: NamedSource::new(ctx.file, expr.clone()),
                bad_bit: (0, 4).into(),
            });
        }
        path = elements[0].to_string();
        format = elements[1..].join(" ");
    }
    match select(&object, &path) {
        Ok(selected_value) => {
            if let Some(selected_value) = selected_value.first() {
                if value_type == "exists" {
                    return Ok((true, expr.clone()));
                }
                match selected_value {
                    Value::Array(v) => {
                        if value_type == "empty" {
                            return Ok((v.is_empty(), expr.clone()));
                        }
                        if value_type == "notEmpty" {
                            return Ok((!v.is_empty(), expr.clone()));
                        }
                        Ok((value_type == "array", expr.clone()))
                    }
                    Value::String(v) => {
                        if value_type == "date" {
                            match NaiveDateTime::parse_from_str(v, format.as_str()) {
                                Ok(_v) => return Ok((true, expr.clone())),
                                Err(e) => match NaiveDate::parse_from_str(v, format.as_str()) {
                                    Ok(_v) => return Ok((true, expr.clone())),
                                    Err(_err) => {
                                        let err_message = format!("Error parsing date: {}", e);
                                        return Err(AssertionError {
                                            advice: Some(err_message),
                                            src: NamedSource::new(ctx.file, expr.clone()),
                                            bad_bit: (0, expr.len()).into(),
                                        });
                                    }
                                },
                            }
                        }
                        if value_type == "empty" {
                            return Ok((v.is_empty(), expr.clone()));
                        }
                        if value_type == "notEmpty" {
                            return Ok((!v.is_empty(), expr.clone()));
                        }
                        Ok((value_type == "str", expr.clone()))
                    }
                    Value::Number(_v) => Ok((value_type == "num", expr.clone())),
                    Value::Bool(_v) => Ok((value_type == "bool", expr.clone())),
                    Value::Null => Ok((value_type == "null", expr.clone())),
                    _ => todo!(),
                }
            } else {
                let mut err_message =
                    "The given json path could not be located in the context".to_string();
                if should_log {
                    err_message += "Add the 'dump: true' to the test step, to print out the requests and responses which can be refered to via jsonpath";
                }
                return Err(AssertionError {
                    advice: Some(err_message),
                    src: NamedSource::new(ctx.file, expr.clone()),
                    bad_bit: (0, expr.len()).into(),
                });
            }
        }
        Err(_err) => {
            // TODO: reproduce and improve this error. Use the _err argument
            // The given jsonpath could not be evaluated to a value
            return Err(AssertionError {
                advice: Some("could not resolve jsonpaths to any real variables".to_string()),
                src: NamedSource::new(ctx.file, expr.clone()),
                bad_bit: (0, 4).into(),
            });
        }
    }
}

async fn check_assertions(
    ctx: TestContext,
    asserts: &[Assert],
    json_body: Value,
    outputs: &HashMap<String, Value>,
    step_log: &mut String,
) -> Vec<Result<bool, AssertionError>> {
    let mut assert_results: Vec<Result<bool, AssertionError>> = Vec::new();
    let should_log = ctx.should_log;
    for assertion in asserts {
        let eval_result = match assertion {
            Assert::IsOk(expr) => {
                evaluate_expressions::<bool>(ctx.clone(), expr, &json_body, outputs)
                    .map(|(e, eval_expr)| ("OK ", e == true, expr, eval_expr))
            }
            Assert::IsArray(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "array")
                .map(|(e, eval_expr)| ("ARRAY ", e == true, expr, eval_expr)),
            Assert::IsEmpty(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "empty")
                .map(|(e, eval_expr)| ("EMPTY ", e == true, expr, eval_expr)),
            Assert::IsString(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "str")
                .map(|(e, eval_expr)| ("STRING ", e == true, expr, eval_expr)),
            Assert::IsNumber(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "num")
                .map(|(e, eval_expr)| ("NUMBER ", e == true, expr, eval_expr)),
            Assert::IsBoolean(expr) => {
                evaluate_value::<bool>(ctx.clone(), expr, &json_body, "bool")
                    .map(|(e, eval_expr)| ("BOOLEAN ", e == true, expr, eval_expr))
            }
            Assert::IsNull(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "null")
                .map(|(e, eval_expr)| ("NULL ", e == true, expr, eval_expr)),
            Assert::Exists(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "exists")
                .map(|(e, eval_expr)| ("EXISTS ", e == true, expr, eval_expr)),
            Assert::IsDate(expr) => evaluate_value::<bool>(ctx.clone(), expr, &json_body, "date")
                .map(|(e, eval_expr)| ("DATE ", e == true, expr, eval_expr)),
            Assert::NotEmpty(expr) => {
                evaluate_value::<bool>(ctx.clone(), expr, &json_body, "notEmpty")
                    .map(|(e, eval_expr)| ("NOT EMPTY ", e == true, expr, eval_expr))
            }
        };

        match eval_result {
            Err(err) => {
                assert_results.push(Err(err.clone()));
                if should_log {
                    log::error!(target:"testkit","{}", report_error((err).into()))
                }
            }
            Ok((prefix, result, expr, _eval_expr)) => {
                assert_results.push(Ok(result));
                if result {
                    let log_val = format!("✅ {: <10}  ⮕   {} ", prefix, expr);
                    step_log.push_str(&log_val);
                    step_log.push_str("\n");
                    if should_log {
                        log::info!(target:"testkit","{}", log_val);
                    }
                } else {
                    let log_val = format!("❌ {: <10}  ⮕   {} ", prefix, expr);
                    step_log.push_str(&log_val);
                    step_log.push_str("\n");
                    if should_log {
                        log::error!(target:"testkit","{}", log_val);
                    }

                    let log_val2 = format!(
                        "{}",
                        report_error(
                            (AssertionError {
                                advice: Some(
                                    "check that you're using correct jsonpaths".to_string(),
                                ),
                                src: NamedSource::new("bad_file.rs", expr.to_string()),
                                bad_bit: (0, 4).into(),
                            })
                            .into(),
                        ),
                    );

                    if should_log {
                        log::error!(target:"testkit","{} ", log_val2)
                    }
                }
            }
        }
    }
    assert_results
}

// parse_expression would take a normalized math-like expression and evaluate it to a premitive or simpler
// value. Eg `5 + 5` becomes `10`
fn parse_expression<T: Clone + 'static>(expr: &str) -> Result<T, Box<dyn std::error::Error>> {
    let engine = Engine::new();
    let result = engine.eval_expression::<T>(expr)?;
    Ok(result)
}

fn yaml_to_json(yaml_str: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Parse the YAML string
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(yaml_str)?;

    // Serialize it to a JSON string
    let json_str = serde_json::to_string(&yaml_value)?;

    Ok(json_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;

    #[derive(Debug, Serialize, Deserialize)]
    struct Todo<'a> {
        pub task: &'a str,
        pub completed: bool,
        pub id: u32,
    }
    #[tokio::test]
    async fn test_json_parse() {
        env_logger::init();
        let val = r#"[
        {"GET":"https://6098f32599011f001713fc6e.mockapi.io/mail",
        "asserts":null,"exports":null,
        "headers":null,"json":null,"params":null,
        "raw":null,"title":"Simple Test 1"
        }]"#;
        let ctx = TestContext {
            plan: Some("plan".into()),
            file_source: "file source".into(),
            file: "file.tk.yaml".into(),
            path: ".".into(),
            step: Some("step_name".into()),
            step_index: 0,
            should_log: true,
        };
        let resp = run_json(ctx.clone(), val.into(), None).await;
        println!("resp {:?}", resp);
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn test_yaml_kitchen_sink() {
        env_logger::init();
        // testing_logger::setup();
        let mut todos = vec![
            Todo {
                task: "task one",
                completed: false,
                id: 1,
            },
            Todo {
                task: "task two",
                completed: false,
                id: 2,
            },
        ];
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(POST)
                .path("/todos")
                .header("content-type", "application/json")
                .json_body(json!({ "task": "hit the gym" }));
            todos.push(Todo {
                task: "hit the gym",
                completed: false,
                id: todos.len() as u32,
            });
            then.status(201).json_body(json!(todos[todos.len() - 1]));
        });
        let m2 = server.mock(|when, then| {
            when.method(GET).path("/todo_get");
            // .json_body(json!({ "req_string": "test"  }));
            then.status(200).json_body(json!({
            "tasks": todos,
             "empty_str": "",
              "empty_arr": [],
             "null_val": null
            }));
        });
        let m3 = server.mock(|when, then| {
            when.method(PUT).path_contains("/todos");
            todos[0].completed = true;
            then.status(200).json_body(json!(todos[0]));
        });
        let m4 = server.mock(|when, then| {
            when.method(DELETE).path("/todos");
            then.status(200)
                .json_body(json!({"task": "task one", "completed": true,"id":1}));
        });

        let yaml_str = format!(
            r#"
---
 - title: step1
   POST: {}
   headers:
     Content-Type: application/json
   json:
     task: hit the gym
   asserts:
     - ok: $.resp.json.task == "hit the gym"
     - ok: $.resp.status == 201
     - number: $.resp.json.id
     - string: $.resp.json.task
     - boolean: $.resp.json.completed
   exports:
     todoResp: $.resp.json.resp_string
 - GET: {}
   json:
     req_string: $.outputs.todoResp
   asserts:
     - ok: $.resp.status == 200
     - array: $.resp.json.tasks
     - ok: $.resp.json.tasks[0].task == "task one"
     - notEmpty: $.resp.json.tasks[0].task
     - notEmpty: $.resp.json.tasks
     - number: $.resp.json.tasks[1].id
     - empty: $.resp.json.empty_str
     - empty: $.resp.json.empty_arr
     #- nil: $.resp.json.null_val
   exports:
     todoId: $.resp.json.tasks[0].id
 - PUT: {}
   asserts:
     - ok: $.resp.json.completed
     - ok: $.resp.json.id == $.steps[1].outputs.todoId
 - DELETE: {}
   asserts:
     - ok: $.resp.json.id == $.steps[-2].outputs.todoId
     - boolean: $.resp.json.completed
     - ok: $.resp.json.task == "task one"
"#,
            server.url("/todos"),
            server.url("/todo_get"),
            server.url("/todos"),
            server.url("/todos")
        );

        let ctx = TestContext {
            plan: Some("plan".into()),
            file_source: "file source".into(),
            file: "file.tk.yaml".into(),
            path: ".".into(),
            step: Some("step_name".into()),
            step_index: 0,
            should_log: true,
        };
        let resp = run(ctx.clone(), yaml_str.clone(), true).await;
        assert!(resp.is_ok());
        m3.assert_hits(1);
        m2.assert_hits(1);
        m4.assert_hits(1);
        m.assert_hits(1);

        // // We test the log output, because the logs are an important part of the user facing API of a cli tool like this
        // // TODO: figure out returning the correct exit code to show error or failure.
        // testing_logger::validate(|captured_logs| {
        //     println!("PPP");
        //     for c in captured_logs {
        //         println!("xx {:?}", c.body);
        //     }
        //     assert_eq!(captured_logs.len(), 1);
        //     // assert_eq!(captured_logs[0].body, "Something went wrong with 10");
        //     // assert_eq!(captured_logs[0].level, Level::Warn);
        // });

        // We test if the kitchen sink also works for json
        let json_str = yaml_to_json(&yaml_str).unwrap();
        let resp = run_json(ctx.clone(), json_str.into(), None).await;
        assert!(resp.is_ok());
        m3.assert_hits(2);
        m2.assert_hits(2);
        m4.assert_hits(2);
        m.assert_hits(2);
        log::info!("{:#?}", resp);
    }
}
