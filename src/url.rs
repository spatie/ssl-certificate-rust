/// A host name and optional TLS port, extracted from a URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Url {
    host: String,
    port: Option<u16>,
}

impl Url {
    /// Parses a bare host, host:port, or HTTP, HTTPS, or SSL URL.
    ///
    /// International domain names are converted to ASCII. Paths are ignored.
    /// The default TLS port is 443, including for HTTP URLs.
    ///
    /// # Errors
    /// Returns [`crate::Error::InvalidUrl`] for an invalid host, scheme, or port.
    pub fn new(input: &str) -> Result<Self, crate::Error> {
        let invalid = || crate::Error::InvalidUrl(input.to_owned());
        if input.is_empty() || input.chars().any(char::is_whitespace) {
            return Err(invalid());
        }
        let authority = if let Some((scheme, rest)) = input.split_once("://") {
            if !["https", "http", "ssl"]
                .iter()
                .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
            {
                return Err(invalid());
            }
            rest
        } else {
            input
        };
        let authority = authority
            .split(['/', '?', '#'])
            .next()
            .ok_or_else(invalid)?;
        let normalized = format!("https://{authority}");
        let parsed = url::Url::parse(&normalized).map_err(|_| invalid())?;
        let host = parsed.host_str().ok_or_else(invalid)?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(invalid());
        }
        let port = if let Some((_, port)) = authority.rsplit_once(':') {
            if authority.ends_with(']') {
                None
            } else {
                Some(port.parse::<u16>().map_err(|_| invalid())?)
            }
        } else {
            None
        };
        Ok(Self {
            host: host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
            port,
        })
    }

    /// Returns the ASCII host name or unbracketed IP address.
    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.host
    }

    /// Returns the explicit port, or 443.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(443)
    }

    pub(crate) fn explicit_port(&self) -> Option<u16> {
        self.port
    }
}
