use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use dnssec_prover::query::{ProofBuilder, QueryBuf};
use dnssec_prover::rr::Name;
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::{verify_rr_stream};
use std::error::Error;

/// This simple example demonstrates how to use the `dnssec‑prover` crate to
/// fetch and validate DNSSEC‑signed TXT records for a Bitcoin payment name.
///
/// Bitcoin payment instructions defined in BIP‑353 are stored in the DNS as
/// TXT records at labels of the form `user._bitcoin‑payment.domain`.  Clients
/// MUST verify DNSSEC signatures when resolving these records.  The
/// `dnssec‑prover` crate exposes a `ProofBuilder` which constructs a proof
/// for a given name/type by repeatedly querying a recursive resolver.  When
/// building proofs via DNS‑over‑HTTPS (DoH) each query buffer should be
/// base64url encoded and sent to a DoH endpoint; the raw response can then
/// be fed back into the builder.  Once no further queries are
/// pending the proof can be finalized and validated.

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Resolve a Bitcoin payment name
    Resolve {
        /// The payment name to resolve
        payment_name: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Resolve { payment_name }) => {
            match resolve(&payment_name).await {
                Ok(json_str) => {
                    // Print the JSON array of TXT records
                    println!("{}", json_str);
                }
                Err(e) => {
                    // Escape backslashes and quotes to produce valid JSON
                    let err = e.to_string().replace('\\', "\\\\").replace('"', "\\\"");
                    println!(r#"{{\"error\":\"{}\"}}"#, err);
                }
            }
        }
        None => {
            // Print error for unsupported or missing command
            println!(r#"{{\"error\":\"unsupported or missing command\"}}"#);
        }
    }
    Ok(())
}

/// Resolve a payment name into TXT records and return a JSON array string.
async fn resolve(payment_name: &str) -> Result<String, Box<dyn Error>> {
    // The human‑readable payment name we want to resolve.  According to BIP‑353
    // this becomes `<user>._bitcoin‑payment.<domain>` in the DNS.
    let name: Name = if payment_name.ends_with('.') {
            payment_name.try_into()
        } else {
            format!("{}.", payment_name).try_into()
        }
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid domain name"))?;

    // The DNS record type we are interested in.  For payment instructions this
    // is TXT (type code 16).  `Txt::TYPE` comes from the `rr` module.
    let rr_type = dnssec_prover::rr::TXT_TYPE;

    // Start a `ProofBuilder` for the given name/type.  The initial query is
    // returned and must be sent to a recursive resolver (via DoH in this
    // example).
    let (mut builder, initial_query) = ProofBuilder::new(&name, rr_type);

    // We'll collect outstanding queries in a vector.  Each query is a DNS
    // message in wire format; we will base64url encode it and send it to a
    // DoH server.  Google's DoH endpoint is used here, but any validating
    // resolver that supports DoH will work (e.g. `https://cloudflare-dns.com/dns-query`).
    let doh_endpoint = "https://dns.google/dns-query";
    let client = reqwest::Client::new();

    // Queue the initial query.  `QueryBuf` implements `Deref` to `[u8]`, so
    // calling `.to_vec()` yields the raw bytes of the DNS request.
    let mut pending_queries: Vec<Vec<u8>> = vec![initial_query.to_vec()];

    while let Some(query_bytes) = pending_queries.pop() {
        // Encode the DNS message using URL‑safe base64 without padding.  When
        // constructing DoH queries the `dnssec_prover` documentation recommends
        // base64url encoding the entire DNS message and placing it in the
        // `dns` query parameter.
        let encoded = URL_SAFE_NO_PAD.encode(&query_bytes);
        let url = format!("{}?dns={}", doh_endpoint, encoded);

        // Send the query to the DoH resolver.  The `Accept` header requests a
        // DNS wire format response (`application/dns‑message`) as required by
        // RFC 8484.  Any non‑200 response is treated as an error.
        let resp = client
            .get(&url)
            .header("Accept", "application/dns-message")
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(format!("DoH query failed: {}", resp.status()).into());
        }
        let bytes = resp.bytes().await?;

        // Wrap the response bytes into a `QueryBuf` for processing.  We
        // allocate a buffer of the correct length and copy the response into
        // it.  The `process_response` method returns any new queries that
        // should be sent to the resolver.
        let mut buf = QueryBuf::new_zeroed(bytes.len() as u16);
        buf.copy_from_slice(&bytes);
        let new_queries = builder
            .process_response(&buf)
            .map_err(|e| format!("Proof building error: {:?}", e))?;
        for q in new_queries {
            pending_queries.push(q.to_vec());
        }
    }

    // Once there are no more pending queries, finalize the proof.  This returns
    // the proof bytes along with the lowest TTL from any of the DNS records
    // involved.  The proof may be cached up to this TTL (measured in seconds).
    let (proof, _ttl) = builder
        .finish_proof()
        .map_err(|_| "proof incomplete or too many queries")?;

    // Deserialize the proof into a list of DNS resource records and verify
    // DNSSEC signatures.  The `verify_rr_stream` function walks the DNSSEC
    // chain from the root trust anchors down to the requested record.
    let rrs = parse_rr_stream(&proof).expect("failed to parse proof");

    // TODO: Improve ValidationError in the dnssec-prover lib
    let verified = match verify_rr_stream(&rrs) {
        Ok(stream) => stream,
        Err(_e) => return Err("Failed to verify resource records".into()),
    };

    // The `valid_from` and `expires` timestamps describe the period during
    // which the proof is valid.  Applications MUST check that the current
    // UNIX time is between these values before trusting the result.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    if now < verified.valid_from || now > verified.expires {
        return Err("proof is not valid at the current time".into());
    }

    // Resolve the TXT records at the original name.  `resolve_name` follows
    // CNAME/DNAME chains automatically and returns only the records matching
    // the requested name.  Each record implements `json()` which produces a
    // JSON representation similar to the one returned by the WASM demo server.
    let results = verified.resolve_name(&name);
    // If no TXT records are found, return an empty JSON array
    if results.is_empty() {
        return Ok("[]".to_string());
    }
    // Collect the verified TXT records into a JSON array.  For Bitcoin payment
    // instructions wallets should ignore any TXT entries that do not start
    // with "bitcoin:"【636381911854922†L88-L91】.  This example just includes all verified
    // strings.
    let mut out = String::from("[");
    for (i, rr) in results.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&rr.json());
    }
    out.push(']');
    Ok(out)
}