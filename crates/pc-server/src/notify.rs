//! Benachrichtigungen per E-Mail (SMTP) und Webhook (Teams, Slack, JSON):
//! neue Befunde, Verschlechterung der Note und Wochenbericht.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{Datelike, Local, NaiveTime, Weekday};
use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::Serialize;
use serde_json::json;
use tracing::{info, warn};

use crate::analysis::{AnalysisSummary, Severity};
use crate::api::AppState;
use crate::config::{NotifyConfig, WebhookConfig};

/// Höchstzahl der Einzelzeilen je Nachricht.
const MAX_LINES: usize = 25;

/// Eine Nachricht, die an alle Kanäle geht.
#[derive(Debug, Clone, Serialize)]
pub struct Note {
    pub subject: String,
    pub intro: String,
    pub lines: Vec<String>,
    /// Pfad in der Weboberfläche, z. B. `/assist`
    pub link: Option<String>,
}

/// Ergebnis je Kanal (für den Testversand in der Oberfläche).
#[derive(Debug, Serialize)]
pub struct Delivery {
    pub channel: String,
    pub ok: bool,
    pub error: Option<String>,
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Kritisch",
        Severity::High => "Hoch",
        Severity::Medium => "Mittel",
        Severity::Low => "Niedrig",
        Severity::Info => "Info",
    }
}

fn link(cfg: &NotifyConfig, path: &Option<String>) -> Option<String> {
    let base = cfg.public_url.as_deref()?.trim_end_matches('/');
    Some(format!("{base}{}", path.as_deref().unwrap_or("/")))
}

fn plain_text(cfg: &NotifyConfig, n: &Note) -> String {
    let mut s = format!("{}\n\n", n.intro);
    for l in &n.lines {
        s.push_str(&format!("- {l}\n"));
    }
    if let Some(u) = link(cfg, &n.link) {
        s.push_str(&format!("\nÖffnen: {u}\n"));
    }
    s.push_str("\n-- \nPermissionCenter\n");
    s
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn html(cfg: &NotifyConfig, n: &Note) -> String {
    let items: String = n
        .lines
        .iter()
        .map(|l| format!("<li>{}</li>", html_escape(l)))
        .collect();
    let button = link(cfg, &n.link)
        .map(|u| {
            format!(
                "<p><a href=\"{u}\" style=\"display:inline-block;padding:8px 14px;background:#18181b;color:#fff;border-radius:6px;text-decoration:none\">In PermissionCenter öffnen</a></p>"
            )
        })
        .unwrap_or_default();
    format!(
        "<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#18181b\">\
         <h2 style=\"font-size:18px\">{}</h2><p>{}</p><ul>{items}</ul>{button}\
         <p style=\"color:#71717a;font-size:12px\">PermissionCenter</p></div>",
        html_escape(&n.subject),
        html_escape(&n.intro)
    )
}

async fn send_mail(cfg: &NotifyConfig, n: &Note) -> Result<()> {
    let s = &cfg.smtp;
    let host = s.host.as_deref().context("SMTP-Host fehlt")?;
    let from: Mailbox = s
        .from
        .as_deref()
        .context("Absender fehlt")?
        .parse()
        .context("Absenderadresse ungültig")?;
    let mut msg = Message::builder().from(from).subject(&n.subject);
    for to in &s.to {
        msg = msg.to(to
            .parse()
            .with_context(|| format!("Empfänger {to} ungültig"))?);
    }
    let msg = msg.multipart(
        MultiPart::alternative()
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(plain_text(cfg, n)),
            )
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_HTML)
                    .body(html(cfg, n)),
            ),
    )?;
    let builder = match s.security.as_str() {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(host)?,
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?,
    };
    let mut builder = builder.port(s.port).timeout(Some(Duration::from_secs(30)));
    if let (Some(u), Some(p)) = (&s.username, &s.password) {
        builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
    }
    builder.build().send(msg).await?;
    Ok(())
}

fn webhook_body(cfg: &NotifyConfig, w: &WebhookConfig, n: &Note) -> serde_json::Value {
    let url = link(cfg, &n.link);
    match w.format.as_str() {
        "teams" => {
            let mut card = json!({
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    { "type": "TextBlock", "text": n.subject, "weight": "Bolder", "size": "Medium", "wrap": true },
                    { "type": "TextBlock", "text": n.intro, "wrap": true },
                    { "type": "TextBlock", "text": n.lines.iter().map(|l| format!("- {l}")).collect::<Vec<_>>().join("\n"), "wrap": true },
                ],
            });
            if let Some(u) = url {
                card["actions"] = json!([{ "type": "Action.OpenUrl", "title": "In PermissionCenter öffnen", "url": u }]);
            }
            json!({
                "type": "message",
                "attachments": [{ "contentType": "application/vnd.microsoft.card.adaptive", "content": card }],
            })
        }
        "json" => json!({ "subject": n.subject, "intro": n.intro, "lines": n.lines, "url": url }),
        _ => {
            let mut text = format!("*{}*\n{}\n", n.subject, n.intro);
            for l in &n.lines {
                text.push_str(&format!("• {l}\n"));
            }
            if let Some(u) = url {
                text.push_str(&format!("<{u}|In PermissionCenter öffnen>"));
            }
            json!({ "text": text })
        }
    }
}

async fn send_webhook(cfg: &NotifyConfig, w: &WebhookConfig, n: &Note) -> Result<()> {
    let body = webhook_body(cfg, w, n);
    let url = w.url.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .build()
            .into();
        let mut res = agent.post(&url).send_json(&body)?;
        let status = res.status();
        if !status.is_success() {
            let text = res.body_mut().read_to_string().unwrap_or_default();
            bail!(
                "HTTP {status}: {}",
                text.chars().take(300).collect::<String>()
            );
        }
        Ok(())
    })
    .await?
}

/// Verschickt eine Nachricht an alle konfigurierten Kanäle.
pub async fn send(cfg: &NotifyConfig, n: &Note) -> Vec<Delivery> {
    let mut out = Vec::new();
    if cfg.smtp_configured() {
        let r = send_mail(cfg, n).await;
        out.push(Delivery {
            channel: format!("E-Mail an {}", cfg.smtp.to.join(", ")),
            ok: r.is_ok(),
            error: r.err().map(|e| format!("{e:#}")),
        });
    }
    for w in &cfg.webhooks {
        let r = send_webhook(cfg, w, n).await;
        // Nur Host anzeigen – Webhook-URLs enthalten geheime Token
        let host = w.url.split('/').nth(2).unwrap_or("?");
        out.push(Delivery {
            channel: format!("Webhook ({}) {host}", w.format),
            ok: r.is_ok(),
            error: r.err().map(|e| format!("{e:#}")),
        });
    }
    for d in &out {
        match &d.error {
            None => info!("Benachrichtigung „{}“ gesendet: {}", n.subject, d.channel),
            Some(e) => warn!("Benachrichtigung an {} fehlgeschlagen: {e}", d.channel),
        }
    }
    out
}

fn min_severity(cfg: &NotifyConfig) -> Option<Severity> {
    match cfg.min_severity.as_str() {
        "off" | "aus" | "" => None,
        s => Some(Severity::parse(s)),
    }
}

/// Erstellt die Nachricht zu einem Analyselauf (oder `None`, wenn nichts zu melden ist).
pub async fn analysis_note(st: &AppState, a: &AnalysisSummary) -> Result<Option<Note>> {
    let cfg = &st.cfg.notify;
    if a.initial {
        return Ok(None);
    }
    let c = st.db.get().await?;
    let hosts: HashMap<i64, String> = c
        .query("SELECT id, hostname FROM systems", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let host = |id: Option<i64>| match id {
        Some(i) => hosts
            .get(&i)
            .cloned()
            .unwrap_or_else(|| format!("System {i}")),
        None => "Active Directory".into(),
    };

    let min = min_severity(cfg);
    let mut news: Vec<_> = a
        .new_findings
        .iter()
        .filter(|f| f.rule == "STALE_SYSTEM" || min.is_some_and(|m| f.severity <= m))
        .collect();
    news.sort_by_key(|f| f.severity);
    let drops: Vec<_> = if cfg.grade_drop {
        a.grade_changes.iter().collect()
    } else {
        Vec::new()
    };
    if news.is_empty() && drops.is_empty() {
        return Ok(None);
    }

    let mut lines = Vec::new();
    for d in &drops {
        let what = match d.scope {
            "total" => "Gesamtbewertung".to_string(),
            "infra" => "Dateisysteme".to_string(),
            "ad" => "Active Directory".to_string(),
            _ => host(Some(d.system_id)),
        };
        lines.push(format!(
            "Note {what}: {} → {} ({} → {} Punkte)",
            d.old_grade, d.new_grade, d.old_score, d.new_score
        ));
    }
    for f in news.iter().take(MAX_LINES) {
        lines.push(format!(
            "[{}] {}: {}",
            severity_label(f.severity),
            host(f.system_id),
            f.title
        ));
    }
    if news.len() > MAX_LINES {
        lines.push(format!("… und {} weitere", news.len() - MAX_LINES));
    }

    let mut counts: Vec<(Severity, usize)> = Vec::new();
    for f in &news {
        match counts.iter_mut().find(|(s, _)| *s == f.severity) {
            Some(c) => c.1 += 1,
            None => counts.push((f.severity, 1)),
        }
    }
    let subject = if news.is_empty() {
        "PermissionCenter: Bewertung verschlechtert".to_string()
    } else {
        format!(
            "PermissionCenter: {} ({})",
            if news.len() == 1 {
                "1 neuer Befund".to_string()
            } else {
                format!("{} neue Befunde", news.len())
            },
            counts
                .iter()
                .map(|(s, n)| format!("{n} {}", severity_label(*s).to_lowercase()))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Ok(Some(Note {
        subject,
        intro: "Bei der letzten Analyse sind folgende Punkte aufgefallen:".into(),
        lines,
        link: Some("/assist".into()),
    }))
}

/// Nach einer Analyse im Hintergrund benachrichtigen.
pub fn after_analysis(st: AppState, a: AnalysisSummary) {
    if !st.cfg.notify.any_channel() {
        return;
    }
    tokio::spawn(async move {
        match analysis_note(&st, &a).await {
            Ok(Some(n)) => {
                send(&st.cfg.notify, &n).await;
            }
            Ok(None) => {}
            Err(e) => warn!("Benachrichtigung konnte nicht erstellt werden: {e:#}"),
        }
    });
}

/// Inhalt des Wochenberichts.
pub async fn weekly_note(st: &AppState) -> Result<Note> {
    let c = st.db.get().await?;
    let c = &**c;
    let score = |scope: &'static str, days: i32| async move {
        c.query_opt(
            "SELECT score, grade FROM score_history WHERE scope = $1 AND system_id = 0
               AND day <= current_date - $2::int ORDER BY day DESC LIMIT 1",
            &[&scope, &days],
        )
        .await
        .map(|r| r.map(|r| (r.get::<_, i32>(0), r.get::<_, String>(1))))
    };
    let now = score("total", 0).await?;
    let before = score("total", 7).await?;
    let mut lines = Vec::new();
    if let Some((s, g)) = &now {
        let trend = match &before {
            Some((b, _)) if b != s => format!(" (vor 7 Tagen: {b})"),
            _ => String::new(),
        };
        lines.push(format!("Gesamtbewertung: Note {g}, {s} Punkte{trend}"));
    }
    let open = c
        .query(
            "SELECT severity, COUNT(*) FROM findings f
             WHERE NOT EXISTS (SELECT 1 FROM finding_states fs WHERE fs.fingerprint = f.fingerprint AND fs.status = 'accepted')
             GROUP BY severity",
            &[],
        )
        .await?;
    let mut sev: Vec<(Severity, i64)> = open
        .iter()
        .map(|r| (Severity::parse(r.get(0)), r.get(1)))
        .collect();
    sev.sort();
    if !sev.is_empty() {
        lines.push(format!(
            "Offene Befunde: {}",
            sev.iter()
                .map(|(s, n)| format!("{n} {}", severity_label(*s).to_lowercase()))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let resolved: i64 = c
        .query_one(
            "SELECT COUNT(*) FROM finding_states WHERE status = 'resolved' AND resolved_at >= now() - interval '7 days'",
            &[],
        )
        .await?
        .get(0);
    lines.push(format!("Behoben in den letzten 7 Tagen: {resolved}"));
    let changes: i64 = c
        .query_one(
            "SELECT COUNT(*) FROM changes WHERE detected_at >= now() - interval '7 days'",
            &[],
        )
        .await?
        .get(0);
    lines.push(format!(
        "Berechtigungsänderungen in den letzten 7 Tagen: {changes}"
    ));
    for r in c
        .query(
            "SELECT title FROM findings WHERE rule = 'STALE_SYSTEM' ORDER BY title",
            &[],
        )
        .await?
    {
        lines.push(r.get::<_, String>(0));
    }
    for r in c
        .query(
            "SELECT y.hostname, h.grade, h.score FROM score_history h JOIN systems y ON y.id = h.system_id
             WHERE h.scope = 'system' AND h.day = (SELECT MAX(day) FROM score_history)
             ORDER BY h.score LIMIT 5",
            &[],
        )
        .await?
    {
        let (host, grade, s): (String, String, i32) = (r.get(0), r.get(1), r.get(2));
        if grade.as_str() > "B" {
            lines.push(format!("Schwächstes System: {host} – Note {grade} ({s} Punkte)"));
        }
    }
    Ok(Note {
        subject: format!(
            "PermissionCenter: Wochenbericht KW {}",
            Local::now().iso_week().week()
        ),
        intro: "Zusammenfassung der letzten 7 Tage:".into(),
        lines,
        link: Some("/".into()),
    })
}

/// Wochentag und Uhrzeit aus z. B. `mo 07:00` bzw. `monday 7:00`.
pub fn parse_schedule(s: &str) -> Option<(Weekday, NaiveTime)> {
    let mut parts = s.split_whitespace();
    let day = parts.next()?.to_lowercase();
    let day = match &day[..2.min(day.len())] {
        "mo" => Weekday::Mon,
        "di" | "tu" => Weekday::Tue,
        "mi" | "we" => Weekday::Wed,
        "do" | "th" => Weekday::Thu,
        "fr" => Weekday::Fri,
        "sa" => Weekday::Sat,
        "so" | "su" => Weekday::Sun,
        _ => return None,
    };
    let time = NaiveTime::parse_from_str(parts.next().unwrap_or("07:00"), "%H:%M").ok()?;
    Some((day, time))
}

/// Prüft minütlich, ob der Wochenbericht fällig ist (einmal je Kalenderwoche).
pub async fn weekly_tick(st: &AppState) -> Result<()> {
    let cfg = &st.cfg.notify;
    let Some((day, time)) = cfg.weekly_summary.as_deref().and_then(parse_schedule) else {
        return Ok(());
    };
    if !cfg.any_channel() {
        return Ok(());
    }
    let now = Local::now();
    if now.weekday() != day || now.time() < time {
        return Ok(());
    }
    let week = format!("{}-W{}", now.iso_week().year(), now.iso_week().week());
    let c = st.db.get().await?;
    if crate::db::get_meta(&**c, "weekly_summary_sent")
        .await?
        .as_deref()
        == Some(week.as_str())
    {
        return Ok(());
    }
    crate::db::set_meta(&**c, "weekly_summary_sent", Some(&week)).await?;
    drop(c);
    let note = weekly_note(st).await?;
    send(cfg, &note).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule() {
        assert_eq!(
            parse_schedule("mo 07:00"),
            Some((Weekday::Mon, NaiveTime::from_hms_opt(7, 0, 0).unwrap()))
        );
        assert_eq!(parse_schedule("Freitag 16:30").unwrap().0, Weekday::Fri);
        assert!(parse_schedule("xx 07:00").is_none());
        assert!(parse_schedule("mo 25:00").is_none());
    }

    #[test]
    fn webhook_formats() {
        let cfg = NotifyConfig {
            public_url: Some("http://pc:8080/".into()),
            ..Default::default()
        };
        let n = Note {
            subject: "S".into(),
            intro: "I".into(),
            lines: vec!["a".into()],
            link: Some("/assist".into()),
        };
        let w = |f: &str| WebhookConfig {
            url: "x".into(),
            format: f.into(),
        };
        let teams = webhook_body(&cfg, &w("teams"), &n);
        assert_eq!(
            teams["attachments"][0]["content"]["actions"][0]["url"],
            "http://pc:8080/assist"
        );
        assert!(webhook_body(&cfg, &w("slack"), &n)["text"]
            .as_str()
            .unwrap()
            .contains("• a"));
    }
}
