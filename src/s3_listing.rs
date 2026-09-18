//! Human S3 listings use the familiar date/size/name layout. Object metadata
//! remains available in JSON; only the human presentation omits it.
use crate::{
    output,
    s3::{ObjectListing, S3Client},
};
use anyhow::{ensure, Result};
use chrono::{DateTime, Local, Utc};
use clap::Args;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io::{self, Write},
};

#[derive(Args, Debug)]
pub struct ListOptions {
    /// List all objects under the prefix, including subfolders.
    #[arg(long)]
    recursive: bool,
    /// Display sizes in Bytes, KiB, MiB, GiB, and TiB.
    #[arg(long)]
    human_readable: bool,
    /// Print the number and total size of the listed objects.
    #[arg(long)]
    summarize: bool,
    /// Results per request (all pages are fetched automatically).
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u16).range(1..=1000))]
    page_size: u16,
}

pub async fn objects(
    s3: &S3Client,
    bucket: &str,
    prefix: &str,
    options: &ListOptions,
    json_output: bool,
) -> Result<()> {
    let mut token = None;
    let mut seen = HashSet::new();
    let mut collected = ObjectListing {
        items: Vec::new(),
        common_prefixes: Vec::new(),
        next: None,
    };
    let mut collected_bytes = 0usize;
    let mut count = 0u64;
    let mut bytes = 0u128;
    loop {
        let page = s3
            .list_objects_page(
                bucket,
                Some(prefix),
                token.as_deref(),
                (!options.recursive).then_some("/"),
                Some(options.page_size),
            )
            .await?;
        count += page.items.len() as u64;
        bytes += page
            .items
            .iter()
            .map(|item| u128::from(item.size.unwrap_or(0)))
            .sum::<u128>();
        let next = page.next.clone();
        if json_output {
            if output::is_jsonl() {
                let mut value = serde_json::to_value(&page)?;
                if next.is_none() && options.summarize {
                    value["summary"] = json!({"total_objects": count, "total_size": bytes});
                }
                output::print(&value, true)?;
            } else {
                collected_bytes += serde_json::to_vec(&page)?.len();
                ensure!(collected_bytes <= 16 * 1024 * 1024,
                    "JSON listing exceeds 16 MiB; use --output jsonl to stream all pages or choose a narrower prefix");
                collected.items.extend(page.items);
                collected.common_prefixes.extend(page.common_prefixes);
            }
        } else {
            let mut stdout = io::stdout().lock();
            write_page(&mut stdout, &page, options)?;
            stdout.flush()?;
        }
        match next {
            Some(next) => {
                ensure!(
                    seen.insert(next.clone()),
                    "S3 returned a repeated continuation token"
                );
                ensure!(
                    seen.len() <= 1_000_000,
                    "S3 listing exceeds client page limit; choose a narrower prefix"
                );
                token = Some(next);
            }
            None => break,
        }
    }
    if json_output && !output::is_jsonl() {
        let mut value = serde_json::to_value(collected)?;
        if options.summarize {
            value["summary"] = json!({"total_objects": count, "total_size": bytes});
        }
        output::print(&value, true)?;
    } else if !json_output && options.summarize {
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "\nTotal Objects: {count}")?;
        writeln!(
            stdout,
            "   Total Size: {}",
            size(bytes, options.human_readable)
        )?;
    }
    Ok(())
}

fn write_page(writer: &mut impl Write, page: &ObjectListing, options: &ListOptions) -> Result<()> {
    for prefix in &page.common_prefixes {
        let name = prefix
            .strip_suffix('/')
            .unwrap_or(prefix)
            .rsplit('/')
            .next()
            .unwrap_or(prefix);
        writeln!(writer, "{:>30} {}/", "PRE", terminal_text(name))?;
    }
    for item in &page.items {
        let name = if options.recursive {
            &item.key
        } else {
            item.key.rsplit('/').next().unwrap_or(&item.key)
        };
        let date = timestamp(item.last_modified.as_deref().map(Value::from).as_ref());
        let size = item
            .size
            .map(|bytes| size(u128::from(bytes), options.human_readable))
            .unwrap_or_else(|| "-".into());
        writeln!(writer, "{date:<19} {size:>10} {}", terminal_text(name))?;
    }
    Ok(())
}

pub fn buckets(value: &Value, json_output: bool) -> Result<()> {
    if json_output {
        return output::print(value, true);
    }
    let items = value["items"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("bucket inventory omitted items"))?;
    let mut rows = Vec::with_capacity(items.len());
    for item in items {
        let name = item
            .as_str()
            .or_else(|| item["name"].as_str())
            .ok_or_else(|| anyhow::anyhow!("bucket inventory item omitted name"))?;
        rows.push((name, timestamp(item.get("created_at"))));
    }
    rows.sort_by(|a, b| a.0.cmp(b.0));
    let mut stdout = io::stdout().lock();
    for (name, date) in rows {
        writeln!(stdout, "{date:<19} {}", terminal_text(name))?;
    }
    Ok(())
}

fn timestamp(value: Option<&Value>) -> String {
    let date = value.and_then(|value| {
        if let Some(value) = value.as_str() {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|date| date.with_timezone(&Utc))
        } else {
            value
                .as_i64()
                .and_then(|value| DateTime::from_timestamp(value, 0))
        }
    });
    date.map(|date| {
        date.with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    })
    .unwrap_or_else(|| "-".into())
}

fn size(bytes: u128, human: bool) -> String {
    if !human {
        return bytes.to_string();
    }
    if bytes < 1024 {
        return format!("{bytes} Bytes");
    }
    let units = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"];
    let mut amount = bytes as f64 / 1024.0;
    let mut unit = 0;
    while amount >= 1024.0 && unit < units.len() - 1 {
        amount /= 1024.0;
        unit += 1;
    }
    format!("{amount:.1} {}", units[unit])
}

// Keys are arbitrary user data. Preserve Unicode and spaces without allowing
// embedded newlines or terminal escape sequences to forge listing rows.
fn terminal_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| {
            if ch.is_control() {
                ch.escape_default().collect::<Vec<_>>()
            } else {
                vec![ch]
            }
        })
        .collect()
}
