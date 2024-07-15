use axum::{
    extract::{Query, State, Form},
    routing::{get, post},
    response::{IntoResponse, Redirect, Html},
    Router,
};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, 
    ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenUrl,
    TokenResponse,
};
use oauth2::basic::BasicClient;
use reqwest::Client;
use reqwest::header::{
    HeaderMap, HeaderValue, AUTHORIZATION
};
use oauth2::reqwest::async_http_client;

use axum::http::StatusCode;
use tokio::fs;

use serde::{Deserialize, Serialize};

use serde_json::{json, from_str, Value};


use tokio::sync::Mutex;

use async_session::Session;

use std::collections::HashMap;
use std::sync::Arc;

struct AppState {
    session: Mutex<Session>,
    config: Config,
    oauth_client: BasicClient,
    pkce_verifier: Mutex<Option<PkceCodeVerifier>>,
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
        session: Mutex::new(Session::new()),
        config,
        oauth_client: client,
        pkce_verifier: Mutex::new(None),
    });

    let app = Router::new()
        .route("/", get(get_home))
        .route("/post_home", post(post_home))
        .route("/login", post(login))
        .route("/callback", get(callback_handler))
        .route("/logout", post(logout))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}



async fn login(State(state): State<Arc<AppState>>) -> impl IntoResponse {

    // Generate a PKCE challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Store the PKCE verifier for later use
    *state.pkce_verifier.lock().await = Some(pkce_verifier);

    // Generate the authorization URL
    let (auth_url, _csrf_token) = state.oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("tweet.read".to_string()))
        .add_scope(Scope::new("tweet.write".to_string()))
        .add_scope(Scope::new("users.read".to_string()))
        .add_scope(Scope::new("offline.access".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    Redirect::to(auth_url.as_str())
}


async fn callback_handler(
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
) -> Redirect {
    if let Some(error) = params.get("error") {
        println!("Error in OAuth callback: {}", error);
        if error == "access_denied" {
            println!("Access denied by user");
        }
        return Redirect::to("/");
    }
    let code = params.get("code").expect("No code in params");

    // Retrieve the PKCE verifier
    let verifier = state.pkce_verifier.lock().await.take().expect("No PKCE verifier found");

    // Exchange the code for a token
    let token_result = state.oauth_client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(verifier)
        .request_async(async_http_client)
        .await;

    match token_result {
        Ok(token) => {
            // Here you would typically store the token securely and use it for API requests
            let mut session = state.session.lock().await;
            session.insert("is_authenticated", true).unwrap();
            let access_token = token.access_token().secret();
            let refresh_token = token.refresh_token().unwrap().secret();
            println!("Successfully authenticated! Access token: {}", access_token);
            println!("Refresh token: {}", refresh_token);
            session.insert("access_token", access_token).unwrap(); 
            session.insert("refresh_token", refresh_token).unwrap();

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
                                session.insert("username", username).unwrap();
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

            Redirect::to("/")
        }
        Err(e) => {
            println!("Failed to authenticate: {:?}", e);
            Redirect::to("/")
        }
    }
}

async fn logout(State(state): State<Arc<AppState>>) -> Redirect {
    let mut session = state.session.lock().await;
    
    let _ = session.remove("is_authenticated");
    let _ = session.remove("access_token");
    let _ = session.remove("refresh_token");
    let _ = session.remove("username");
    
    println!("Logged out!");
    
    // Redirect to home page
    Redirect::to("/")
}


async fn post_to_x(content: &str, access_token: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Posting to X");
    let client = Client::new();
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
        Err(format!("X API error: {}", response.status()).into())
    }
}


#[derive(Deserialize)]
struct PostForm {
    content: String,
}

async fn post_home(
    State(state): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Form(form): Form<PostForm>
) -> Result<Redirect, (StatusCode, Html<String>)> {
    let session = state.session.lock().await;
    let is_authenticated = session.get::<bool>("is_authenticated").unwrap_or(false);
     
    if is_authenticated {
        println!("is_authenticated");
        // User is authenticated, post to X
        match post_to_x(&form.content, &session.get::<String>("access_token").unwrap_or_default()).await {
            Ok(_) => {
                println!("Successfully posted to X");
                Ok(Redirect::to("/")) // Redirect to home on success
            },
            Err(e) => {
                eprintln!("Error posting to X: {}", e);
                Err((StatusCode::INTERNAL_SERVER_ERROR, Html(format!("<h1>Error posting to X</h1><p>{}</p>", e))))
            }
        }
    } else {
        // User is not authenticated, redirect to home
        println!("User not authenticated");
        Ok(Redirect::to("/"))
    }

}


async fn get_home(State(state): State<Arc<AppState>>) -> Result<Html<String>, StatusCode> {
    let session = state.session.lock().await;
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
            <h1>Welcome to Write2X! Here you can post to X platform. Yes that's all. Why? Because now you can post that great thought without getting lost in the algorithms. Your access token is stored in your browser, so you don't have to trust us with it. Code is on github so you can check how this works if you want.</h1>
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

