mod filters;
mod http;
mod model;
mod stream;

use clap::Parser;
use filters::Filters;
use model::Request;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Write};
use std::ops::ControlFlow;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "CLI filter tool for requests and responses",
    long_about = None,
    after_help = "Filters are ANDed and case-sensitive.\n\nExamples:\n  httpql --file log.json --list.urls\n  httpql --file log.json --list.urls --req.url.contains example.com\n  httpql --file log.json --req.method.contains POST\n  httpql --file log.json --req.headers.contains 'Authorization: Bearer'\n  httpql --file log.json --resp.body.contains error\n  httpql --file log.json --id 91"
)]
struct Args {
    /// Path to the JSON log file.
    #[arg(short, long = "file", value_name = "FILE")]
    file: PathBuf,

    /// Print unique request URLs only.
    #[arg(long = "list.urls")]
    list_urls: bool,

    /// Print decoded raw request and response for the given request id(s).
    #[arg(long = "id", value_name = "ID", num_args = 1.., conflicts_with = "list_urls")]
    ids: Vec<u64>,

    /// Include requests whose URL contains this text.
    #[arg(long = "req.url.contains")]
    req_url_contains: Option<String>,

    /// Exclude requests whose URL contains this text.
    #[arg(long = "req.url.ncontains")]
    req_url_ncontains: Option<String>,

    /// Include requests whose method contains this text.
    #[arg(long = "req.method.contains")]
    req_method_contains: Option<String>,

    /// Exclude requests whose method contains this text.
    #[arg(long = "req.method.ncontains")]
    req_method_ncontains: Option<String>,

    /// Include requests whose headers contain this text.
    #[arg(long = "req.headers.contains")]
    req_headers_contains: Option<String>,

    /// Exclude requests whose headers contain this text.
    #[arg(long = "req.headers.ncontains")]
    req_headers_ncontains: Option<String>,

    /// Include requests whose body contains this text.
    #[arg(long = "req.body.contains")]
    req_body_contains: Option<String>,

    /// Exclude requests whose body contains this text.
    #[arg(long = "req.body.ncontains")]
    req_body_ncontains: Option<String>,

    /// Include requests whose full decoded raw request contains this text.
    #[arg(long = "req.raw.contains")]
    req_raw_contains: Option<String>,

    /// Exclude requests whose full decoded raw request contains this text.
    #[arg(long = "req.raw.ncontains")]
    req_raw_ncontains: Option<String>,

    /// Include requests whose response headers contain this text.
    #[arg(long = "resp.headers.contains")]
    resp_headers_contains: Option<String>,

    /// Exclude requests whose response headers contain this text.
    #[arg(long = "resp.headers.ncontains")]
    resp_headers_ncontains: Option<String>,

    /// Include requests whose response body contains this text.
    #[arg(long = "resp.body.contains")]
    resp_body_contains: Option<String>,

    /// Exclude requests whose response body contains this text.
    #[arg(long = "resp.body.ncontains")]
    resp_body_ncontains: Option<String>,

    /// Include requests whose full decoded raw response contains this text.
    #[arg(long = "resp.raw.contains")]
    resp_raw_contains: Option<String>,

    /// Exclude requests whose full decoded raw response contains this text.
    #[arg(long = "resp.raw.ncontains")]
    resp_raw_ncontains: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let file = File::open(&args.file)?;
    let reader = BufReader::new(file);

    let filters = Filters {
        req_url_contains: args.req_url_contains,
        req_url_ncontains: args.req_url_ncontains,
        req_method_contains: args.req_method_contains,
        req_method_ncontains: args.req_method_ncontains,
        req_headers_contains: args.req_headers_contains,
        req_headers_ncontains: args.req_headers_ncontains,
        req_body_contains: args.req_body_contains,
        req_body_ncontains: args.req_body_ncontains,
        req_raw_contains: args.req_raw_contains,
        req_raw_ncontains: args.req_raw_ncontains,
        resp_headers_contains: args.resp_headers_contains,
        resp_headers_ncontains: args.resp_headers_ncontains,
        resp_body_contains: args.resp_body_contains,
        resp_body_ncontains: args.resp_body_ncontains,
        resp_raw_contains: args.resp_raw_contains,
        resp_raw_ncontains: args.resp_raw_ncontains,
    };

    if !args.ids.is_empty() {
        return print_raw_by_id(reader, &args.ids, &filters);
    }

    if args.list_urls {
        return list_urls(reader, &filters);
    }

    list_method_urls(reader, &filters)
}

fn list_urls(
    reader: impl std::io::Read,
    filters: &Filters,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut matched: u64 = 0;
    let mut write_error: Option<std::io::Error> = None;

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    stream::stream_json_array::<Request, _>(reader, |request| {
        let url = model::build_url(&request);
        if filters.matches(&request, &url) {
            matched += 1;
            if seen.insert(url.clone()) && !record_write(writeln!(out, "{}", url), &mut write_error)
            {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    })?;

    let broken_pipe = is_broken_pipe(&write_error);
    finish_output(&mut out, write_error)?;
    if broken_pipe {
        return Ok(());
    }

    eprintln!(
        "Matched {} request(s), {} unique URL(s)",
        matched,
        seen.len()
    );
    Ok(())
}

fn list_method_urls(
    reader: impl std::io::Read,
    filters: &Filters,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut matched: u64 = 0;
    let mut write_error: Option<std::io::Error> = None;

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    stream::stream_json_array::<Request, _>(reader, |request| {
        let url = model::build_url(&request);
        if filters.matches(&request, &url) {
            matched += 1;
            if !record_write(
                writeln!(out, "{} {}", request.method, url),
                &mut write_error,
            ) {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    })?;

    let broken_pipe = is_broken_pipe(&write_error);
    finish_output(&mut out, write_error)?;
    if broken_pipe {
        return Ok(());
    }

    eprintln!("Matched {} request(s)", matched);
    Ok(())
}

fn print_raw_by_id(
    reader: impl std::io::Read,
    ids: &[u64],
    filters: &Filters,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut remaining: HashSet<u64> = ids.iter().copied().collect();
    let mut found: HashSet<u64> = HashSet::new();
    let mut write_error: Option<std::io::Error> = None;

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    stream::stream_json_array::<Request, _>(reader, |request| {
        if !remaining.contains(&request.id) {
            return ControlFlow::Continue(());
        }

        let url = model::build_url(&request);
        if !filters.matches(&request, &url) {
            return ControlFlow::Continue(());
        }

        let request_bytes = match http::decode_base64(&request.raw) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!(
                    "Failed to decode request {} raw HTTP: {}",
                    request.id, error
                );
                found.insert(request.id);
                remaining.remove(&request.id);
                return if remaining.is_empty() {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                };
            }
        };

        if !record_write(
            writeln!(
                out,
                "===== REQUEST {}: {} {} =====",
                request.id, request.method, url
            ),
            &mut write_error,
        ) {
            return ControlFlow::Break(());
        }
        if !record_write(out.write_all(&request_bytes), &mut write_error) {
            return ControlFlow::Break(());
        }
        if !request_bytes.ends_with(b"\n") && !record_write(out.write_all(b"\n"), &mut write_error)
        {
            return ControlFlow::Break(());
        }

        match &request.response {
            Some(response) => {
                if !record_write(
                    writeln!(
                        out,
                        "===== RESPONSE {}: {} =====",
                        request.id, response.status_code
                    ),
                    &mut write_error,
                ) {
                    return ControlFlow::Break(());
                }

                match http::decode_base64(&response.raw) {
                    Ok(response_bytes) => {
                        if !record_write(out.write_all(&response_bytes), &mut write_error) {
                            return ControlFlow::Break(());
                        }
                        if !response_bytes.ends_with(b"\n")
                            && !record_write(out.write_all(b"\n"), &mut write_error)
                        {
                            return ControlFlow::Break(());
                        }
                    }
                    Err(error) => {
                        eprintln!(
                            "Failed to decode response for request {} (response id {}): {}",
                            request.id, response.id, error
                        );
                        if !record_write(
                            writeln!(out, "(response body could not be decoded)"),
                            &mut write_error,
                        ) {
                            return ControlFlow::Break(());
                        }
                    }
                }
            }
            None => {
                if !record_write(
                    writeln!(
                        out,
                        "===== RESPONSE {}: (no response recorded) =====",
                        request.id
                    ),
                    &mut write_error,
                ) {
                    return ControlFlow::Break(());
                }
            }
        }

        found.insert(request.id);
        remaining.remove(&request.id);

        if remaining.is_empty() {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })?;

    let broken_pipe = is_broken_pipe(&write_error);
    finish_output(&mut out, write_error)?;
    if broken_pipe {
        return Ok(());
    }

    if !remaining.is_empty() {
        let mut missing: Vec<u64> = remaining.into_iter().collect();
        missing.sort_unstable();
        eprintln!("Request id(s) not found or filtered out: {:?}", missing);
    }

    if found.is_empty() {
        return Err("no matching request ids found".into());
    }

    Ok(())
}

fn record_write(result: std::io::Result<()>, error: &mut Option<std::io::Error>) -> bool {
    match result {
        Ok(()) => true,
        Err(err) => {
            *error = Some(err);
            false
        }
    }
}

fn is_broken_pipe(error: &Option<std::io::Error>) -> bool {
    error
        .as_ref()
        .map(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
        .unwrap_or(false)
}

fn finish_output(
    out: &mut impl Write,
    write_error: Option<std::io::Error>,
) -> Result<(), Box<dyn std::error::Error>> {
    let flush_result = out.flush();

    if let Some(error) = write_error {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(error.into());
    }

    match flush_result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}
