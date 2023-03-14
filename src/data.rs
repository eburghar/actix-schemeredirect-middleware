use actix_web::{
	http::header::{HeaderValue, TryIntoHeaderPair, TryIntoHeaderValue, STRICT_TRANSPORT_SECURITY},
	HttpResponse,
};
use serde::{Deserialize, Deserializer};
use std::{convert::Infallible, fmt::Display, time::Duration};

#[derive(Deserialize, Clone)]
/// https redirection configuration
pub struct Redirect {
	/// ssl port
	pub port: Option<u16>,
	/// redirect to tls port for ipv4,ipv6 or both protocols
	pub protocols: Protocols,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocols {
	IPv4,
	IPv6,
	Both,
	None,
}

impl Default for Protocols {
	fn default() -> Self {
		Protocols::None
	}
}

#[derive(Deserialize, Clone)]
/// hsts headers configuration
pub struct StrictTransportSecurity {
	/// custom duration in seconds (300s)
	#[serde(default = "default_duration", deserialize_with = "duration_deser")]
	pub duration: Duration,
	/// include subdomains (false)
	#[serde(default)]
	pub include_subdomains: bool,
	/// add preload directive (false)
	#[serde(default)]
	pub preload: bool,
}

fn default_duration() -> Duration {
	Duration::from_secs(300)
}

// Deserialize a Duration from an integer than represents seconds
fn duration_deser<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
	let s: u64 = Deserialize::deserialize(d)?;
	Ok(Duration::from_secs(s))
}

impl Default for StrictTransportSecurity {
	fn default() -> Self {
		Self {
			duration: Duration::from_secs(300),
			include_subdomains: false,
			preload: false,
		}
	}
}

impl Display for StrictTransportSecurity {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let secs = self.duration.as_secs();
		let subdomains = if self.include_subdomains {
			"; includeSubDomains"
		} else {
			""
		};
		let preload = if self.preload { "; preload" } else { "" };
		write!(f, "max-age={secs}{subdomains}{preload}")
	}
}

impl StrictTransportSecurity {
	pub fn insert_into<B>(&self, res: &mut HttpResponse<B>) {
		res.headers_mut().insert(
			STRICT_TRANSPORT_SECURITY,
			HeaderValue::from_str(&self.to_string()).unwrap(),
		);
	}
}

impl TryIntoHeaderValue for StrictTransportSecurity {
	type Error = Infallible;

	fn try_into_value(self) -> Result<HeaderValue, Self::Error> {
		let sts = HeaderValue::from_str(&self.to_string()).unwrap();
		Ok(sts)
	}
}

impl TryIntoHeaderPair for StrictTransportSecurity {
	type Error = Infallible;

	fn try_into_pair(
		self,
	) -> Result<(actix_web::http::header::HeaderName, HeaderValue), Self::Error> {
		let value = self.try_into_value()?;
		Ok((STRICT_TRANSPORT_SECURITY, value))
	}
}
