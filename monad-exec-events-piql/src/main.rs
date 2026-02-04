use std::{
    convert::Infallible, error::Error, future::IntoFuture, path::PathBuf, sync::Arc, time::Duration,
};

use axum::{
    Json,
    extract::{Query, State},
    response::{
        IntoResponse, Sse,
        sse::{Event, KeepAlive},
    },
};
use clap::{CommandFactory, FromArgMatches, Parser};
use futures::Stream;
use monad_block_capture::BlockCaptureBlockArchive;
use piql::QueryEngine;
use polars::{
    frame::DataFrame,
    io::SerWriter,
    prelude::{DslPlan, IntoLazy, IpcStreamWriter, LazyFrame},
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use simplelog::{ColorChoice, CombinedLogger, Config, LevelFilter, TermLogger, TerminalMode};
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_swagger_ui::SwaggerUi;

use crate::claude::ClaudeClient;

use self::block_archive::{BlockArchive, BlockProcessorHarness};

mod block_archive;
mod claude;

#[derive(Debug, Parser)]
#[command(name = "monad-exec-event-piql", about, long_about = None)]
pub struct Cli {
    #[arg(long)]
    block_archive_path: PathBuf,

    #[arg(long)]
    port: u16,
}

fn main() {
    let mut cmd = Cli::command();

    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])
    .unwrap_or_else(|err| {
        cmd.error(clap::error::ErrorKind::Io, err.to_string())
            .exit()
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| cmd.error(clap::error::ErrorKind::Io, e).exit());

    if let Err(e) = runtime.block_on(run(cmd)) {
        panic!("monad-exec-event-piqla crashed: {:?}", e);
    }
}

async fn run(mut cmd: clap::Command) -> Result<(), Box<dyn Error>> {
    let Cli {
        block_archive_path,
        port,
    } = Cli::from_arg_matches_mut(&mut cmd.get_matches_mut())?;

    let block_archive = Arc::new(BlockArchive::new(block_archive_path));

    let claude_client = ClaudeClient::new();

    let app_state = Arc::new(AppState {
        block_archive,
        claude_client,
    });

    let (router, openapi) = OpenApiRouter::new()
        .routes(routes!(piql))
        .routes(routes!(query))
        .with_state(app_state)
        .layer(
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST])
                .allow_origin(tower_http::cors::Any),
        )
        .split_for_parts();

    let router = router.merge(SwaggerUi::new("/swagger-ui").url("/openapi.json", openapi.clone()));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap();

    Ok(axum::serve(listener, router).into_future().await?)
}

struct AppState {
    block_archive: Arc<BlockArchive>,
    claude_client: ClaudeClient,
}

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams)]
pub struct PiqlQuery {
    prompt: String,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct PiqlResponse {
    piql: Option<String>,
    error: Option<String>,
}

#[utoipa::path(
    get,
    path = "/piql",
    params(
        PiqlQuery
    ),
    responses(
        (status = 200, body = PiqlResponse),
    )
)]
async fn piql(State(state): State<Arc<AppState>>, query: Query<PiqlQuery>) -> Json<PiqlResponse> {
    let Query(PiqlQuery { prompt }) = query;

    const SYSTEM_PROMPT: &'static str = include_str!("piql_system_prompt.txt");

    let piql = match state
        .claude_client
        .generate_piql(SYSTEM_PROMPT, &prompt)
        .await
    {
        Err(err) => {
            return Json(PiqlResponse {
                piql: None,
                error: Some(err.to_string()),
            });
        }
        Ok(piql) => piql,
    };

    if piql.is_empty() {
        return Json(PiqlResponse {
            piql: None,
            error: Some("Failed to generate PIQL".to_string()),
        });
    }

    eprintln!("{piql}");

    let expr = match piql::advanced::parse(&piql) {
        Err(err) => {
            return Json(PiqlResponse {
                piql: None,
                error: Some(err.to_string()),
            });
        }
        Ok(expr) => expr,
    };

    println!("{expr:#?}");

    Json(PiqlResponse {
        piql: Some(piql),
        error: None,
    })
}

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams)]
pub struct QueryQuery {
    block_from: u64,
    block_to: u64,

    query: String,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct QueryResponse {
    #[schema(
        value_type = Option<String>,
        format = "byte",
    )]
    #[serde_as(as = "Option<Base64>")]
    df: Option<Vec<u8>>,

    error: Option<String>,
}

#[utoipa::path(
    get,
    path = "/query",
    params(
        QueryQuery
    ),
    responses(
        (status = 200, body = QueryResponse),
    )
)]
async fn query(
    State(state): State<Arc<AppState>>,
    query: Query<QueryQuery>,
) -> Json<QueryResponse> {
    let Query(QueryQuery {
        block_from,
        block_to,
        query,
    }) = query;

    let mut query_engine = QueryEngine::new();

    query_engine.add_base_df("tx_headers", {
        let mut procesor = state
            .block_archive
            .create_tx_header_scanner(block_from, block_to)
            .create_processor();

        let mut df = DataFrame::default();

        while let Some(df_next) = procesor.next().unwrap() {
            df.vstack_mut_owned(df_next).unwrap();
        }

        df.lazy()
    });

    let value = match query_engine.query(&query) {
        Err(err) => {
            return Json(QueryResponse {
                df: None,
                error: Some(err.to_string()),
            });
        }
        Ok(value) => value,
    };

    let lf = match value {
        piql::Value::DataFrame(lf, _) => lf,
        _ => {
            return Json(QueryResponse {
                df: None,
                error: Some("Query does not produce dataframe".to_string()),
            });
        }
    };

    let mut df_buf = Vec::default();

    let () = IpcStreamWriter::new(&mut df_buf)
        .finish(&mut lf.collect().unwrap())
        .unwrap();

    Json(QueryResponse {
        df: Some(df_buf),
        error: None,
    })
}
