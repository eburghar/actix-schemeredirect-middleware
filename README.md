Define a middleware one can use to redirect unsecure HTTP connection to TLS and setup HSTS headers

Lamely based on
[RedirectHttps](https://docs.rs/actix-web-lab/latest/actix_web_lab/middleware/struct.RedirectHttps.html),
with a predicate to perform the redirect based on which protocol (IPv4 or IPv6) is used and
with a simpler StrictTransportSecurity that doesn't need parsing.

```rust
use actix_files::Files;
use actix_schemeredirect_middleware::{
	middleware::{Protocols, SchemeRedirect},
	strict_transport_security::StrictTransportSecurity,
};
use actix_web::{App, HttpServer};
use anyhow::Result;
use std::time::Duration;

async fn serve() -> Result<()> {
	let port = 443;
	let hsts = StrictTransportSecurity {
		duration: Duration::from_secs(300),
		include_subdomains: true,
		preload: true,
	};
	let server = HttpServer::new(move || {
		App::new()
			.wrap(SchemeRedirect::new(
				Protocols::Both,
				Some(hsts.clone()),
				Some(port),
			))
			.service(Files::new("/", "/var/www").index_file("index.html"))
	});
	// serve
	server.run().await?;
	Ok(())
}
```
