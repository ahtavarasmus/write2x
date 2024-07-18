use axum::{
    http::StatusCode,
    extract::{Query, State, Form},
    routing::{get, post},
    response::{IntoResponse, Redirect, Html, Response},
    Router,
};
use oauth2::{
    StandardTokenResponse, EmptyExtraTokenFields, basic::BasicTokenType,
    AuthUrl, AuthorizationCode, ClientId, 
    ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenUrl,
    TokenResponse,
    basic::BasicClient,
    reqwest::async_http_client
};
use tower_sessions::{Session, SessionManagerLayer, Expiry, MemoryStore};
use std::time::{SystemTime, Duration};
use reqwest::{Client,header::{HeaderMap, HeaderValue, AUTHORIZATION}
};
use base64::encode;

use tokio::fs;

use serde::{Deserialize, Serialize};

use serde_json::{json, from_str, Value};


use tokio::sync::Mutex;


use std::collections::HashMap;
use std::sync::Arc;


#[derive(Debug)]
pub struct AppError(pub anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}


struct AppState {
    config: Config,
    oauth_client: BasicClient,
    pkce_verifier: Mutex<Option<PkceCodeVerifier>>,
}

impl AppState {
    pub async fn refresh_access_token(&self) -> Result<(), Box<dyn std::error::Error>> {
        let access_token = session.get::<String>("access_token").unwrap_or_default();
        let refresh_token = session.get::<String>("refresh_token").unwrap_or_default();
        let expiration_time = session.get::<SystemTime>("access_token_expiration_time").unwrap_or(SystemTime::UNIX_EPOCH);

        let url = "https://api.twitter.com/2/oauth2/token";
    
        let client = Client::new();

        let basic_auth_str = format!("{}:{}", self.config.values.get("X_CLIENT_ID").expect("Couldn't retrieve X_CLIENT_ID when refreshing token").to_string(), self.config.values.get("X_CLIENT_SECRET").expect("Couldn't retrieve X_CLIENT_SECRET when refreshing token").to_string());
        let basic_auth_encoded = encode(basic_auth_str);

        let response = client.post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", format!("Basic {}", basic_auth_encoded))
            .form(&[
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token".to_string()),
            ])
            .send()
            .await?;

        let new_tokens: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType> = response.json().await?;

        let new_access_token = new_tokens.access_token().secret();
        let new_refresh_token = new_tokens.refresh_token().unwrap().secret();
        let new_expires_in = new_tokens.expires_in().unwrap();
        let new_expiration_time = SystemTime::now() + Duration::from_secs(new_expires_in as u64);

        session.insert("access_token", new_access_token).unwrap();
        session.insert("refresh_token", new_refresh_token).unwrap();
        session.insert("access_token_expiration_time", new_expiration_time).unwrap();
        println!("Refreshed access token");
        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Config {
    #[serde(flatten)]
    pub values: HashMap<String, String>,
}

async fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let config_file_path = "/etc/write2x_config.json";
    let contents = fs::read_to_string(config_file_path).await?;
    let config: Config = from_str(&contents)?;
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config().await?;
    println!("Config: {:?}", config);

    // Initialize the OAuth client
    let client = BasicClient::new(
            ClientId::new(config.values.get("X_CLIENT_ID").expect("X_CLIENT_ID not found in config").to_string()),
            Some(ClientSecret::new(config.values.get("X_CLIENT_SECRET").expect("X_CLIENT_SECRET not found in config").to_string())),
            AuthUrl::new("https://x.com/i/oauth2/authorize".to_string())?,
            Some(TokenUrl::new("https://api.twitter.com/2/oauth2/token".to_string())?)
        )
        .set_redirect_uri(RedirectUrl::new(config.values.get("X_REDIRECT_URL").expect("X_REDIRECT_URL not found in config").to_string())?);


    let state = Arc::new(AppState {
        config,
        oauth_client: client,
        pkce_verifier: Mutex::new(None),
    });

    // Create a session store
    let session_store = MemoryStore::default();
    
    // Create the session layer
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false);


    let app = Router::new()
        .route("/", get(get_home))
        .route("/post_home", post(post_home))
        .route("/login", post(login))
        .route("/callback", get(callback_handler))
        .route("/logout", post(logout))
        .layer(session_layer)
        .with_state(state);
        

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn token_needs_refresh(session: Session) -> bool {
    let current_time = SystemTime::now();
    current_time < session.await.get::<SystemTime>("expiration_time").unwrap_or(SystemTime::UNIX_EPOCH)
}


async fn login(
        session: Session, 
        State(state): State<Arc<AppState>>
    ) -> Result<Redirect, AppError> {

    // Generate a PKCE challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Store the PKCE verifier for later use
    session.insert("pkce_verifier", pkce_verifier.secret()).await?;

    // Generate the authorization URL
    let (auth_url, _csrf_token) = state.oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("tweet.read".to_string()))
        .add_scope(Scope::new("tweet.write".to_string()))
        .add_scope(Scope::new("users.read".to_string()))
        .add_scope(Scope::new("offline.access".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    session.insert("_csrf_token", _csrf_token.secret()).await?;
    Ok(Redirect::to(auth_url.as_str()))
}


async fn callback_handler(
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
    mut session: Session
) -> Result<Redirect, AppError> {
    if let Some(error) = params.get("error") {
        println!("Error in OAuth callback: {}", error);
        if error == "access_denied" {
            println!("Access denied by user");
        }
        return Ok(Redirect::to("/"))
    }
    let code = params.get("code").expect("No code in params");

    // Retrieve the PKCE verifier
    let verifier = session.get("pkce_verifier").await?
            .ok_or_else(|| AppError(anyhow::anyhow!("PKCE verifier not found in session")))?;

    // Exchange the code for a token
    let token_result = state.oauth_client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(verifier)
        .request_async(async_http_client)
        .await;

    match token_result {
        Ok(token) => {
            session.insert("is_authenticated", true).await?;
            let access_token = token.access_token().secret();
            let refresh_token = token.refresh_token().unwrap().secret();
            let token_creation_time = SystemTime::now();
            let expires_in = token.expires_in().unwrap_or(Duration::from_secs(3600));
            let expiration_time = token_creation_time + Duration::from_secs(expires_in.as_secs());
            println!("Successfully authenticated!");
            session.insert("access_token", access_token).await?;
            session.insert("refresh_token", refresh_token).await?;
            session.insert("access_token_expiration_time", expiration_time).await?;

            // Create a client
            let client = reqwest::Client::new();

            // Create headers
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", &access_token)).unwrap());

            match client.get("https://api.twitter.com/2/users/me")
                .headers(headers)
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<Value>().await {
                        Ok(json) => {
                            println!("Twitter API Response: {:?}", json);
                            if let Some(id) = json.get("data").and_then(|data| data.get("id")) {
                                println!("User ID: {}", id);
                            }
                            if let Some(username) = json.get("data").and_then(|data| data.get("username")) {
                                println!("Username: {}", username);
                                session.insert("username", username).await?;
                            }
                        },
                        Err(e) => println!("Failed to parse JSON: {:?}", e),
                    }
                    } else {
                        println!("Twitter API request failed with status: {:?}", response.status());
                    }

                },
                Err(e) => println!("Failed to send request to Twitter API: {:?}", e),

            }

            Ok(Redirect::to("/"))
        }
        Err(e) => {
            println!("Failed to authenticate: {:?}", e);
            Ok(Redirect::to("/"))
        }
    }
}

async fn logout(State(state): State<Arc<AppState>>, mut session: Session) -> impl IntoResponse {
    
    session.clear().await;
    
    println!("Logged out!");
    
    // Redirect to home page
    Redirect::to("/")
}


async fn post_to_x(content: &str, session: Session) -> Result<(), AppError> {
    println!("Posting to X");
    let client = Client::new();
    let access_token: Option<String> = session.get::<String>("access_token").await
        .unwrap_or(None)
        .unwrap_or_else(|| String::new());
    let response = client
        .post("https://api.twitter.com/2/tweets")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&json!({
            "text": content
        }))
        .send()
        .await?;

    if response.status().is_success() {
        println!("Successfully posted to X");
        Ok(())
    } else {
        println!("Failed to post to X: {}", response.status());
        Err(AppError(anyhow::anyhow!("Failed to post to X: {}", response.status())))
    }
}


#[derive(Deserialize)]
struct PostForm {
    content: String,
}

async fn post_home(
    State(state): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Form(form): Form<PostForm>,
    session: Session
) -> Result<Html<String>, AppError> {
    let is_authenticated: Option<bool> = session.get("is_authenticated").await.unwrap_or(None);
     
    match is_authenticated {

        Some(true) => {
            println!("is_authenticated");
            // User is authenticated, post to X
            match post_to_x(&form.content, session).await {
                Ok(_) => {
                    Ok(Html("<h1>Posted to X</h1>".to_string()))
                }
                Err(e) => {
                    Err(e)
                }
            }
        }
        Some(false) => {
            // User is not authenticated, redirect to home
            println!("User not authenticated");
            Ok(Html("<h1>Not authenticated</h1><p>You need to be authenticated to post</p>".to_string()))
        }
        None => {
            // User is not authenticated, redirect to home
            println!("User not authenticated.");
            Ok(Html("<h1>Not authenticated.</h1><p>You need to be authenticated to post</p>".to_string()))
        }
    }

}


async fn get_home(
    State(state): State<Arc<AppState>>,
    session: Session
    ) -> Result<Html<String>, StatusCode> {

    let is_authenticated = session.get::<bool>("is_authenticated").unwrap_or(false);
    let username = session.get::<String>("username").unwrap_or("unknown user".to_string());

    let body = if is_authenticated {
        println!("Authenticated user {}", &username);
        format!(
            r#"
            <h1>Hey, {}!</h1>
            <form action="/post_home" method="post">
                <textarea name="content" cols="30" rows="10"></textarea>
                <br>
                <input type="submit" value="Post">
            </form>
            <br>
            <br>
            <br>
            <form action="/logout" method="post">
                <button type="submit">Disconnect</button>
            </form>
            "#,
            &username
        )
    } else {
        println!("Unauthenticated user");
        format!(
            r#"
            <h1>Welcome to Write2X!</h1> 
            <p>Here you can post to 𝕏 platform. Yes that's all. Why? Because now you can post that great thought without getting lost in the algorithms. Your access token will be stored in your browser, so you don't have to trust us with it. Code is on <a href="https://github.com/ahtavarasmus/write2x" target="_blank">github</a> so you can check how this works if you want.</p>
            <form action="/login" method="post">
                <button type="submit">Connect to 𝕏</button>
            </form>
            "#
        )
    };
    let html = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Write2X</title>
        </head>
        <body>
            {}
        </body>
        </html>
        "#,
        body
    );
    Ok(Html(html))
}

