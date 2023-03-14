use actix_utils::future::{ready, Ready};
use actix_web::{
	body::EitherBody,
	dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
	web, Error, HttpResponse, Responder,
};
use futures_core::future::LocalBoxFuture;
use std::{net::SocketAddr, rc::Rc};

use crate::data::{Protocols, StrictTransportSecurity};

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.

#[derive(Clone, Default)]
pub struct SchemeRedirect {
	protocols: Protocols,
	hsts: Option<StrictTransportSecurity>,
	port: Option<u16>,
}

impl SchemeRedirect {
	pub fn new(
		protocols: Protocols,
		hsts: Option<StrictTransportSecurity>,
		port: Option<u16>,
	) -> Self {
		Self {
			protocols,
			hsts,
			port,
		}
	}

	pub fn to_port(mut self, port: u16) -> Self {
		self.port = Some(port);
		self
	}
}
// Middleware factory is `Transform` trait from actix-service crate
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for SchemeRedirect
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
	S::Future: 'static,
	B: 'static,
{
	type Response = ServiceResponse<EitherBody<B, ()>>;
	type Error = Error;
	type Transform = SchemeRedirectMiddleware<S>;
	type InitError = ();
	type Future = Ready<Result<Self::Transform, Self::InitError>>;

	fn new_transform(&self, service: S) -> Self::Future {
		ready(Ok(SchemeRedirectMiddleware {
			service: Rc::new(service),
			protocols: self.protocols.clone(),
			hsts: self.hsts.clone(),
			port: self.port,
		}))
	}
}

pub struct SchemeRedirectMiddleware<S> {
	service: Rc<S>,
	protocols: Protocols,
	hsts: Option<StrictTransportSecurity>,
	port: Option<u16>,
}

impl<S, B> Service<ServiceRequest> for SchemeRedirectMiddleware<S>
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
	S::Future: 'static,
	B: 'static,
{
	type Response = ServiceResponse<EitherBody<B, ()>>;
	type Error = Error;
	type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

	forward_ready!(service);

	fn call(&self, req: ServiceRequest) -> Self::Future {
		let service = Rc::clone(&self.service);
		let port = self.port;
		let hsts = self.hsts.clone();
		// check if we need to redirect
		let to_redirect = !matches!(self.protocols, Protocols::None)
			&& req
				.peer_addr()
				.and_then(|a| match a {
					// V6 can represent IPv4 connexion
					SocketAddr::V6(ip6) => {
						// this is really an IPv4 connexion if we can map the IPv6 to IPv4
						if ip6.ip().to_ipv4_mapped().is_some() {
							if matches!(self.protocols, Protocols::IPv4 | Protocols::Both) {
								Some(())
							} else {
								None
							}
						// this is a real IPv6 connexion
						} else if matches!(self.protocols, Protocols::IPv6 | Protocols::Both) {
							Some(())
						} else {
							None
						}
					}
					// No ambiguity there
					SocketAddr::V4(_)
						if matches!(self.protocols, Protocols::IPv4 | Protocols::Both) =>
					{
						Some(())
					}
					_ => None,
				})
				.is_some();

		Box::pin(async move {
			let (req, pl) = req.into_parts();
			let conn_info = req.connection_info();
			if to_redirect && conn_info.scheme() != "https" {
				let host = conn_info.host();
				let (hostname, _port) = host.split_once(':').unwrap_or((host, ""));
				let path = req.uri().path();
				let uri = match port {
					Some(port) => format!("https://{hostname}:{port}{path}"),
					None => format!("https://{hostname}{path}"),
				};
				// all connection info is acquired
				drop(conn_info);

				// create redirection response
				let redirect = web::Redirect::to(uri);

				let mut res = redirect.respond_to(&req).map_into_right_body();
				apply_hsts(&mut res, hsts);

				return Ok(ServiceResponse::new(req, res));
			}

			drop(conn_info);

			let req = ServiceRequest::from_parts(req, pl);
			service.call(req).await.map(|mut res| {
				apply_hsts(res.response_mut(), hsts);
				res.map_into_left_body()
			})
		})
	}
}

/// Apply HSTS config to an `HttpResponse`.
fn apply_hsts<B>(res: &mut HttpResponse<B>, hsts: Option<StrictTransportSecurity>) {
	if let Some(hsts) = hsts {
		hsts.insert_into(res);
	}
}
