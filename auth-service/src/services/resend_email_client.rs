use color_eyre::eyre::Result;
use reqwest::{Client, Url};
use secrecy::{ExposeSecret, SecretString};

use crate::domain::{Email, EmailClient};

pub struct ResendEmailClient {
    http_client: Client,
    base_url: String,
    sender: Email,
    api_key: SecretString,
}

impl ResendEmailClient {
    pub fn new(
        base_url: String,
        sender: Email,
        api_key: SecretString,
        http_client: Client,
    ) -> Self {
        Self {
            http_client,
            base_url,
            sender,
            api_key,
        }
    }
}

#[async_trait::async_trait]
impl EmailClient for ResendEmailClient {
    #[tracing::instrument(name = "Sending email", skip_all)]
    async fn send_email(&self, recipient: &Email, subject: &str, content: &str) -> Result<()> {
        let base = Url::parse(&self.base_url)?;
        let url = base.join("/emails")?;

        let request_body = SendEmailRequest {
            from: &format!("Auth Service <{}>", self.sender.as_ref().expose_secret()),
            to: &[recipient.as_ref().expose_secret()],
            subject,
            html: content,
        };

        self.http_client
            .post(url)
            .header(
                RESEND_AUTH_HEADER,
                format!("Bearer {}", self.api_key.expose_secret()),
            )
            .json(&request_body)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}

const RESEND_AUTH_HEADER: &str = "Authorization";

#[derive(serde::Serialize, Debug)]
struct SendEmailRequest<'a> {
    from: &'a str,
    to: &'a [&'a str],
    subject: &'a str,
    html: &'a str,
}

#[cfg(test)]
mod tests {
    use crate::utils::constants::test;

    use super::*;
    use fake::faker::internet::en::SafeEmail;
    use fake::faker::lorem::en::{Paragraph, Sentence};
    use fake::{Fake, Faker};
    use wiremock::matchers::{any, header, header_exists, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    fn subject() -> String {
        Sentence(1..2).fake()
    }

    fn content() -> String {
        Paragraph(1..10).fake()
    }

    fn email() -> Email {
        Email::parse(SecretString::new(
            SafeEmail().fake::<String>().into_boxed_str(),
        ))
        .unwrap()
    }

    fn email_client(base_url: String) -> ResendEmailClient {
        let http_client = Client::builder()
            .timeout(test::email_client::TIMEOUT)
            .build()
            .unwrap();
        ResendEmailClient::new(
            base_url,
            email(),
            SecretString::new(Faker.fake::<String>().into_boxed_str()),
            http_client,
        )
    }

    struct SendEmailBodyMatcher;

    impl wiremock::Match for SendEmailBodyMatcher {
        fn matches(&self, request: &Request) -> bool {
            let result: Result<serde_json::Value, _> = serde_json::from_slice(&request.body);
            if let Ok(body) = result {
                body.get("from").is_some()
                    && body.get("to").is_some()
                    && body.get("subject").is_some()
                    && body.get("html").is_some()
            } else {
                false
            }
        }
    }

    #[tokio::test]
    async fn send_email_sends_the_expected_request() {
        let mock_server = MockServer::start().await;
        let email_client = email_client(mock_server.uri());

        Mock::given(header_exists(RESEND_AUTH_HEADER))
            .and(header("Content-Type", "application/json"))
            .and(path("/emails"))
            .and(method("POST"))
            .and(SendEmailBodyMatcher)
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let outcome = email_client
            .send_email(&email(), &subject(), &content())
            .await;

        assert!(outcome.is_ok());
    }

    #[tokio::test]
    async fn send_email_fails_if_the_server_returns_500() {
        let mock_server = MockServer::start().await;
        let email_client = email_client(mock_server.uri());

        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let outcome = email_client
            .send_email(&email(), &subject(), &content())
            .await;

        assert!(outcome.is_err());
    }

    #[tokio::test]
    async fn send_email_times_out_if_the_server_takes_too_long() {
        let mock_server = MockServer::start().await;
        let email_client = email_client(mock_server.uri());

        let response = ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(180));
        Mock::given(any())
            .respond_with(response)
            .expect(1)
            .mount(&mock_server)
            .await;

        let outcome = email_client
            .send_email(&email(), &subject(), &content())
            .await;

        assert!(outcome.is_err());
    }
}
