# 说明
腾讯云短信发送接口实现

# 示例
```rust
//发送
let response = libs::tencent_sms::TencentSms::new(
        "secret_id",
        "secret_key",
        "sdk_app_id",
        "template_id",
        "sign",
        vec![
            String::from("+8612345678912"),
            String::from("+8612345678913"),
        ],
        vec![String::from("1234"), String::from("5678")],
    )
    .send()
    .await;

//检查是否发送成功
    println!(
        "{:#?}",
        response
            .unwrap()
            .check_is_success(String::from("+8612345678912"))
    );
```