use chrono::{DateTime, Local};
use crypto_hash::{hex_digest, Algorithm};
use hmac::crypto_mac::Output;
use hmac::{Hmac, Mac, NewMac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::Duration;
use awc::{Client, Connector};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TencentSms {
    request_host: String,
    request_content_type: String,
    request_method: String,
    request_params: SmsRequestParams,
    now_at: DateTime<Local>,
    service: String,
    sign_method: String,
    request_type: String,
    secret_id: String,
    secret_key: String,
}

impl TencentSms {
    pub fn new(
        secret_id: &str,
        secret_key: &str,
        sdk_app_id: &str,
        template_id: &str,
        sign: &str,
        phones: Vec<String>,
        template_params: Vec<String>,
    ) -> Self {
        let sms_request_params = SmsRequestParams::new(
            phones,
            template_id.to_string(),
            sign.to_string(),
            template_params,
            sdk_app_id.to_string(),
        );
        Self {
            request_host: String::from("sms.tencentcloudapi.com"),
            request_content_type: String::from("application/json; charset=utf-8"),
            request_method: String::from("POST"),
            request_params: sms_request_params,
            now_at: Local::now(),
            service: String::from("sms"),
            sign_method: String::from("TC3-HMAC-SHA256"),
            request_type: String::from("tc3_request"),
            secret_id: secret_id.to_string(),
            secret_key: secret_key.to_string(),
        }
    }

    fn get_request_payload(&self) -> String {
        match self.request_method.as_str() {
            "POST" => {
                let payload = serde_json::to_string(&self.request_params).unwrap();

                hex_digest(Algorithm::SHA256, payload.as_bytes())
            }
            "GET" => String::new(),
            _ => String::new(),
        }
    }

    fn get_canonical_request(&self) -> String {
        let url = "/";

        let query_string = match self.request_method.as_str() {
            "POST" => String::from(""),
            "GET" => String::from(""), //todo
            _ => String::from(""),
        };

        let request_payload = self.get_request_payload();

        let canonical_request = format!(
            "{}\n{}\n{}\ncontent-type:{}\nhost:{}\n\ncontent-type;host\n{}",
            self.request_method,
            url,
            query_string,
            self.request_content_type,
            self.request_host,
            request_payload
        );

        hex_digest(Algorithm::SHA256, canonical_request.as_bytes())
    }

    fn get_signature(&self) -> String {
        let timestamp = self.now_at.timestamp();
        let t = timestamp.to_string();
        let timestamp_str = t.as_str();
        let date = self.get_date();

        let canonical_request = self.get_canonical_request();

        println!("{:#?}", canonical_request);

        let sign_string = format!(
            "{}\n{}\n{}/{}/{}\n{}",
            self.sign_method,
            timestamp_str,
            self.get_date(),
            self.service,
            self.request_type,
            canonical_request
        );

        let secret_date = self.hmac(
            format!("TC3{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let secret_service = self.hmac(&*secret_date.into_bytes(), self.service.as_bytes());

        let secret_signing = self.hmac(&*secret_service.into_bytes(), self.request_type.as_bytes());

        let signature_sha256 = self.hmac(&*secret_signing.into_bytes(), sign_string.as_bytes());

        let signature = hex::encode(signature_sha256.into_bytes());

        signature
    }

    fn authorization(&self) -> String {
        let authorization = format!(
            "{} Credential={}/{}/{}/{}, SignedHeaders=content-type;host, Signature={}",
            self.sign_method,
            self.secret_id,
            self.get_date(),
            self.service,
            self.request_type,
            self.get_signature()
        );
        authorization
    }

    async fn request(&self) -> Result<Response, &'static str> {
        let url = "https://sms.tencentcloudapi.com/";

        let request_params = self.request_params.get_body_or_query_string();

        let connector = Connector::new().timeout(Duration::from_secs(10)).finish();
        let client = Client::builder()
            .connector(connector)
            .timeout(Duration::from_secs(10))
            .finish();

        let response = client
            .post(url)
            .set_header("X-TC-Action", "SendSms")
            .set_header("X-TC-Timestamp", self.now_at.timestamp().to_string())
            .set_header("X-TC-Version", "2019-07-11")
            .set_header("Content-Type", self.request_content_type.clone())
            .set_header("Host", self.request_host.clone())
            .set_header("Authorization", self.authorization())
            .send_json(request_params)
            .await;

        match response {
            Ok(mut res) => {
                let json: Result<Response, _> = res.json().await;
                match json {
                    Ok(response) => Ok(response),
                    Err(e) => {
                        error!("发送短信时解析响应出现错误: {:?}", e);
                        Err("发送短信时解析响应出现错误")
                    }
                }
            }
            Err(e) => {
                error!("发送短信时发送错误: {:?}", e);
                Err("发送短信时发送错误")
            }
        }
    }

    pub async fn send(&self) -> Result<Response, &'static str> {
        self.request().await
    }

    fn hmac(&self, key: &[u8], content: &[u8]) -> Output<Hmac<Sha256>> {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_varkey(key).expect("HMAC can take key of any size");
        mac.update(content);
        let result = mac.finalize();

        result
    }

    fn get_date(&self) -> String {
        self.now_at.naive_utc().date().to_string()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SmsRequestParams {
    /*#[serde(rename(serialize = "Action"))]
    action: String,*/
    #[serde(rename(serialize = "PhoneNumberSet"))]
    phone_number_set: Vec<String>,
    #[serde(rename(serialize = "TemplateID"))]
    template_id: String,
    #[serde(rename(serialize = "Sign"))]
    sign: String,
    #[serde(rename(serialize = "TemplateParamSet"))]
    template_param_set: Vec<String>,
    #[serde(rename(serialize = "SmsSdkAppid"))]
    sms_sdk_app_id: String,
}
impl SmsRequestParams {
    pub fn new(
        phone_number_set: Vec<String>,
        template_id: String,
        sign: String,
        template_param_set: Vec<String>,
        sms_sdk_app_id: String,
    ) -> Self {
        Self {
            phone_number_set,
            template_id,
            sign,
            template_param_set,
            sms_sdk_app_id,
        }
    }

    pub fn get_body_or_query_string(&self) -> &SmsRequestParams {
        self
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Response {
    #[serde(rename(deserialize = "Response"))]
    response: ResponseSub,
}

impl Response {
    pub fn check_is_success(&self, mobile: String) -> bool {
        for send_status in self.response.send_status_set.clone().into_iter() {
            if send_status.phone_number == mobile {
                return send_status.code == String::from("Ok");
            }
        }
        false
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ResponseSub {
    #[serde(rename(deserialize = "SendStatusSet"))]
    send_status_set: Vec<ResponseSubItem>,
    #[serde(rename(deserialize = "RequestId"))]
    request_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ResponseSubItem {
    #[serde(rename(deserialize = "SerialNo"))]
    seria_no: String,
    #[serde(rename(deserialize = "PhoneNumber"))]
    phone_number: String,
    #[serde(rename(deserialize = "Fee"))]
    fee: i64,
    #[serde(rename(deserialize = "SessionContext"))]
    session_context: String,
    #[serde(rename(deserialize = "Code"))]
    code: String,
    #[serde(rename(deserialize = "Message"))]
    message: String,
    #[serde(rename(deserialize = "IsoCode"))]
    iso_code: String,
}
