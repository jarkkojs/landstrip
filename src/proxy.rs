// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use crate::policy::DomainPolicy;
use http::header::{CONNECTION, CONTENT_LENGTH, HOST};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use url::Url;

const MAX_HTTP_HEADER: usize = 64 * 1024;
const MAX_HTTP_HEADERS: usize = 64;

pub(crate) struct NetworkProxies {
    pub(crate) domain_policy: DomainPolicy,
    pub(crate) http_listener: TcpListener,
    pub(crate) http_addr: SocketAddr,
    pub(crate) socks_listener: TcpListener,
    pub(crate) socks_addr: SocketAddr,
}

#[derive(Clone, Copy)]
pub(crate) enum ProxyProtocol {
    Http,
    Socks,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn accept_proxy(
    listener: &TcpListener,
    domain_policy: &DomainPolicy,
    protocol: ProxyProtocol,
) {
    for client in listener.incoming().flatten() {
        let domain_policy = domain_policy.clone();
        thread::spawn(move || {
            let _ = (|| -> Result<()> {
                match protocol {
                    ProxyProtocol::Http => {
                        let mut client = client;
                        let mut buffer = Vec::new();
                        let mut chunk = [0_u8; 1024];
                        let request: Request<Vec<u8>> = loop {
                            let count = client.read(&mut chunk)?;
                            if count == 0 {
                                return Err(Error::ProxyIncompleteHttpRequest);
                            }
                            buffer.extend_from_slice(&chunk[..count]);

                            if buffer.len() > MAX_HTTP_HEADER {
                                return Err(Error::ProxyHttpHeaderTooLarge);
                            }

                            let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
                            let mut parsed = httparse::Request::new(&mut headers);
                            let header_len = match parsed
                                .parse(&buffer)
                                .map_err(|_| Error::ProxyInvalidHttpRequest)?
                            {
                                httparse::Status::Complete(header_len) => header_len,
                                httparse::Status::Partial => continue,
                            };

                            let method = parsed
                                .method
                                .ok_or(Error::ProxyMissingHttpMethod)?
                                .parse::<Method>()
                                .map_err(|_| Error::ProxyInvalidHttpMethod)?;
                            let uri = parsed
                                .path
                                .ok_or(Error::ProxyMissingHttpTarget)?
                                .parse::<Uri>()
                                .map_err(|_| Error::ProxyInvalidHttpTarget)?;
                            let version =
                                match parsed.version.ok_or(Error::ProxyMissingHttpVersion)? {
                                    0 => Version::HTTP_10,
                                    1 => Version::HTTP_11,
                                    2 => Version::HTTP_2,
                                    _ => return Err(Error::ProxyNotSupportedHttpVersion),
                                };

                            let mut builder =
                                Request::builder().method(method).uri(uri).version(version);
                            let request_headers = builder
                                .headers_mut()
                                .ok_or(Error::ProxyInvalidHttpRequest)?;
                            for header in parsed
                                .headers
                                .iter()
                                .filter(|header| !header.name.is_empty())
                            {
                                let name = header
                                    .name
                                    .parse::<http::HeaderName>()
                                    .map_err(|_| Error::ProxyInvalidHttpHeaderName)?;
                                let value = http::HeaderValue::from_bytes(header.value)
                                    .map_err(|_| Error::ProxyInvalidHttpHeaderValue)?;
                                request_headers.append(name, value);
                            }

                            let body = buffer[header_len..].to_vec();
                            break builder
                                .body(body)
                                .map_err(|_| Error::ProxyInvalidHttpRequest)?;
                        };

                        let target = if *request.method() == Method::CONNECT {
                            let (host, port) = parse_authority(&request.uri().to_string(), 443)?;
                            HttpTarget::Connect { host, port }
                        } else if let Some(scheme) = request.uri().scheme_str() {
                            if scheme != "http" {
                                return Err(Error::ProxyNotSupportedProxyUrlScheme);
                            }

                            let host = request
                                .uri()
                                .host()
                                .ok_or(Error::ProxyMissingProxyUrlHost)?
                                .to_owned();
                            let port = request.uri().port_u16().unwrap_or(80);
                            let uri = request
                                .uri()
                                .path_and_query()
                                .map_or("/", http::uri::PathAndQuery::as_str)
                                .parse::<Uri>()
                                .map_err(|_| Error::ProxyInvalidProxyUrlPath)?;

                            HttpTarget::Forward { host, port, uri }
                        } else {
                            let host = request
                                .headers()
                                .get(HOST)
                                .ok_or(Error::ProxyMissingAuthorityHeader)?
                                .to_str()
                                .map_err(|_| Error::ProxyInvalidAuthorityHeader)?;
                            let (host, port) = parse_authority(host, 80)?;
                            HttpTarget::Forward {
                                host,
                                port,
                                uri: request.uri().clone(),
                            }
                        };

                        let (host, port) = match &target {
                            HttpTarget::Connect { host, port }
                            | HttpTarget::Forward { host, port, .. } => (host, *port),
                        };

                        if !domain_policy.allows_host(host) {
                            write_http_response(&mut client, StatusCode::FORBIDDEN, "Forbidden")?;
                            return Ok(());
                        }

                        let upstream = TcpStream::connect((host.as_str(), port))?;
                        match target {
                            HttpTarget::Connect { .. } => {
                                write_http_response(
                                    &mut client,
                                    StatusCode::OK,
                                    "Connection Established",
                                )?;
                                relay(client, upstream)?;
                                Ok(())
                            }
                            HttpTarget::Forward { uri, .. } => {
                                let version = match request.version() {
                                    Version::HTTP_10 => "HTTP/1.0",
                                    Version::HTTP_2 => "HTTP/2.0",
                                    Version::HTTP_3 => "HTTP/3.0",
                                    _ => "HTTP/1.1",
                                };
                                let mut forwarded =
                                    format!("{} {} {version}\r\n", request.method(), uri)
                                        .into_bytes();
                                for (name, value) in request.headers() {
                                    forwarded.extend_from_slice(name.as_str().as_bytes());
                                    forwarded.extend_from_slice(b": ");
                                    forwarded.extend_from_slice(value.as_bytes());
                                    forwarded.extend_from_slice(b"\r\n");
                                }
                                forwarded.extend_from_slice(b"\r\n");

                                let mut upstream = upstream;
                                upstream.write_all(&forwarded)?;
                                upstream.write_all(request.body())?;
                                relay(client, upstream)?;
                                Ok(())
                            }
                        }
                    }
                    ProxyProtocol::Socks => {
                        let mut client = client;
                        let mut header = [0_u8; 2];
                        client.read_exact(&mut header)?;
                        if header[0] != 5 {
                            return Err(Error::ProxyNotSupportedSocksVersion);
                        }

                        let mut methods = vec![0_u8; usize::from(header[1])];
                        client.read_exact(&mut methods)?;
                        if !methods.contains(&0) {
                            client.write_all(&[5, 0xff])?;
                            return Ok(());
                        }
                        client.write_all(&[5, 0])?;

                        let mut request = [0_u8; 4];
                        client.read_exact(&mut request)?;
                        if request[0] != 5 {
                            return Err(Error::ProxyNotSupportedSocksRequestVersion);
                        }
                        if request[1] != 1 {
                            write_socks_reply(&mut client, 7)?;
                            return Ok(());
                        }

                        let (host, port) = match request[3] {
                            3 => {
                                let mut len = [0_u8; 1];
                                client.read_exact(&mut len)?;
                                let mut host = vec![0_u8; usize::from(len[0])];
                                client.read_exact(&mut host)?;
                                let host = String::from_utf8(host)
                                    .map_err(|_| Error::ProxyInvalidSocksDomain)?;
                                let mut port = [0_u8; 2];
                                client.read_exact(&mut port)?;

                                (host, u16::from_be_bytes(port))
                            }
                            1 => {
                                discard_socks_addr(&mut client, 4)?;
                                write_socks_reply(&mut client, 8)?;
                                return Ok(());
                            }
                            4 => {
                                discard_socks_addr(&mut client, 16)?;
                                write_socks_reply(&mut client, 8)?;
                                return Ok(());
                            }
                            _ => {
                                write_socks_reply(&mut client, 8)?;
                                return Ok(());
                            }
                        };

                        if !domain_policy.allows_host(&host) {
                            write_socks_reply(&mut client, 2)?;
                            return Ok(());
                        }

                        let Ok(upstream) = TcpStream::connect((host.as_str(), port)) else {
                            write_socks_reply(&mut client, 5)?;
                            return Ok(());
                        };

                        write_socks_reply(&mut client, 0)?;
                        relay(client, upstream)?;
                        Ok(())
                    }
                }
            })();
        });
    }
}

fn write_http_response(stream: &mut TcpStream, status: StatusCode, reason: &str) -> Result<()> {
    let response = Response::builder()
        .status(status)
        .header(CONTENT_LENGTH, "0")
        .header(CONNECTION, "close")
        .body(())
        .map_err(|_| Error::ProxyInvalidHttpResponse)?;

    write!(stream, "HTTP/1.1 {} {reason}\r\n", response.status())?;
    for (name, value) in response.headers() {
        stream.write_all(name.as_str().as_bytes())?;
        stream.write_all(b": ")?;
        stream.write_all(value.as_bytes())?;
        stream.write_all(b"\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    Ok(())
}

enum HttpTarget {
    Connect { host: String, port: u16 },
    Forward { host: String, port: u16, uri: Uri },
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16)> {
    let url =
        Url::parse(&format!("http://{authority}/")).map_err(|_| Error::ProxyInvalidAuthority)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::ProxyAuthorityHasUserinfo);
    }

    let host = url
        .host_str()
        .ok_or(Error::ProxyAuthorityMissingHost)?
        .to_owned();
    Ok((host, url.port().unwrap_or(default_port)))
}

fn discard_socks_addr(stream: &mut TcpStream, len: usize) -> io::Result<()> {
    let mut addr = vec![0_u8; len + 2];
    stream.read_exact(&mut addr)
}

fn write_socks_reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
}

fn relay(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client;
    let mut upstream_read = upstream.try_clone()?;
    let mut upstream_write = upstream;

    let to_upstream = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        result
    });
    let to_client = thread::spawn(move || {
        let result = io::copy(&mut upstream_read, &mut client_write);
        let _ = client_write.shutdown(Shutdown::Write);
        result
    });

    let _ = to_upstream.join();
    let _ = to_client.join();
    Ok(())
}
