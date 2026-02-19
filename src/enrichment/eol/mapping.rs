//! Product mapping: resolves SBOM components to endoflife.date product slugs.

use crate::model::Component;

/// Resolved product mapping result.
pub struct ResolvedProduct {
    /// The endoflife.date product slug
    pub product: String,
    /// The version string to match against cycles
    pub version: String,
}

/// Maps SBOM components to endoflife.date product slugs.
pub struct ProductMapper {
    /// Known product list from the API (lowercase for matching)
    product_list: Vec<String>,
}

impl ProductMapper {
    /// Create a new mapper with the known product list.
    #[must_use]
    pub fn new(product_list: Vec<String>) -> Self {
        Self { product_list }
    }

    /// Resolve a component to a product slug and version.
    ///
    /// Tries three strategies in order:
    /// 1. Static PURL mapping
    /// 2. Runtime detection
    /// 3. Fuzzy match against known product list
    #[must_use]
    pub fn resolve(&self, component: &Component) -> Option<ResolvedProduct> {
        let version = component.version.as_deref()?;

        // Strategy 1: PURL-based static mapping
        if let Some(purl) = &component.identifiers.purl
            && let Some((purl_type, purl_name)) = parse_purl_type_name(purl)
                && let Some(product) = static_purl_to_product(&purl_type, &purl_name) {
                    return Some(ResolvedProduct {
                        product: product.to_string(),
                        version: version.to_string(),
                    });
                }

        // Strategy 2: Runtime detection (component IS the runtime)
        if let Some(ecosystem) = &component.ecosystem {
            let eco_str = ecosystem.to_string();
            if let Some(product) = detect_runtime(&eco_str, &component.name) {
                return Some(ResolvedProduct {
                    product: product.to_string(),
                    version: version.to_string(),
                });
            }
        }

        // Strategy 3: Fuzzy match against known product list
        if let Some(product) = self.fuzzy_match_product(&component.name) {
            return Some(ResolvedProduct {
                product,
                version: version.to_string(),
            });
        }

        None
    }

    /// Conservative fuzzy match against the known product list.
    fn fuzzy_match_product(&self, name: &str) -> Option<String> {
        let lower = name.to_lowercase();

        // Exact match (case-insensitive)
        if self.product_list.contains(&lower) {
            return Some(lower);
        }

        // Strip common suffixes and retry
        for suffix in &["-server", "-client", "-core", "-runtime", "-lib"] {
            if let Some(stripped) = lower.strip_suffix(suffix)
                && self.product_list.contains(&stripped.to_string()) {
                    return Some(stripped.to_string());
                }
        }

        None
    }
}

/// Parse PURL type and name from a PURL string.
///
/// E.g. `pkg:pypi/django@4.2.0` → `("pypi", "django")`
fn parse_purl_type_name(purl: &str) -> Option<(String, String)> {
    let without_scheme = purl.strip_prefix("pkg:")?;
    let (type_and_rest, _version) = without_scheme
        .split_once('@')
        .unwrap_or((without_scheme, ""));
    let (purl_type, name_path) = type_and_rest.split_once('/')?;

    // Handle namespaced PURLs (e.g. pkg:npm/%40angular/core)
    // Take the last path segment as the name for matching
    let name = if name_path.contains('/') {
        // For scoped packages, use the full scoped name for mapping
        name_path.to_string()
    } else {
        name_path.to_string()
    };

    Some((purl_type.to_lowercase(), name.to_lowercase()))
}

/// Static PURL type+name to endoflife.date product slug mapping.
///
/// Returns `None` for unknown mappings (conservative).
fn static_purl_to_product(purl_type: &str, purl_name: &str) -> Option<&'static str> {
    // Exact matches by (type, name)
    let result = match (purl_type, purl_name) {
        // Python ecosystem
        ("pypi", "django") => "django",
        ("pypi", "flask") => "flask",
        ("pypi", "numpy") => "numpy",
        ("pypi", "scipy") => "scipy",
        ("pypi", "pandas") => "pandas",
        ("pypi", "celery") => "celery",

        // JavaScript/Node ecosystem
        ("npm", "angular") | ("npm", "%40angular/core") | ("npm", "@angular/core") => "angular",
        ("npm", "react") => "react",
        ("npm", "vue") => "vue",
        ("npm", "next") => "next",
        ("npm", "nuxt") => "nuxt",
        ("npm", "express") => "express",
        ("npm", "jquery") => "jquery",
        ("npm", "bootstrap") => "bootstrap",
        ("npm", "electron") => "electron",

        // Java ecosystem
        ("maven", "spring-boot") | ("maven", "org.springframework.boot/spring-boot") => {
            "spring-boot"
        }
        ("maven", "spring-framework")
        | ("maven", "org.springframework/spring-core") => "spring-framework",
        ("maven", "tomcat") | ("maven", "org.apache.tomcat/tomcat") => "tomcat",
        ("maven", "log4j") | ("maven", "org.apache.logging.log4j/log4j-core") => "log4j",

        // .NET ecosystem
        ("nuget", "microsoft.aspnetcore") | ("nuget", "aspnetcore") => "dotnet",

        // Rust ecosystem
        ("cargo", "tokio") => "tokio",

        // Go ecosystem
        ("golang", "kubernetes") | ("golang", "k8s.io/kubernetes") => "kubernetes",
        ("golang", "go") => "go",

        // System packages — databases
        ("deb" | "rpm" | "apk", name) => {
            return static_system_package(name);
        }

        // Ruby ecosystem
        ("gem", "rails") | ("gem", "actionpack") | ("gem", "activerecord") => "ruby-on-rails",
        ("gem", "ruby") => "ruby",

        // PHP ecosystem
        ("composer", "laravel/framework") | ("composer", "laravel") => "laravel",
        ("composer", "symfony/symfony") | ("composer", "symfony") => "symfony",

        _ => return None,
    };

    Some(result)
}

/// Map system package names (deb/rpm/apk) to endoflife.date products.
fn static_system_package(name: &str) -> Option<&'static str> {
    // Exact matches first
    let exact = match name {
        "nginx" | "nginx-full" | "nginx-light" => return Some("nginx"),
        "apache2" | "httpd" => return Some("apache"),
        "redis-server" | "redis" => return Some("redis"),
        "memcached" => return Some("memcached"),
        "mariadb-server" | "mariadb" => return Some("mariadb"),
        "mysql-server" | "mysql" => return Some("mysql"),
        "rabbitmq-server" | "rabbitmq" => return Some("rabbitmq"),
        "openssh-server" | "openssh" => return Some("openssh"),
        "openssl" | "libssl3" | "libssl-dev" => return Some("openssl"),
        "curl" | "libcurl4" => return Some("curl"),
        _ => None,
    };
    if exact.is_some() {
        return exact;
    }

    // Prefix matching for versioned system packages
    if name.starts_with("postgresql") || name.starts_with("libpq") {
        return Some("postgresql");
    }
    if name.starts_with("python3") || name.starts_with("libpython3") {
        return Some("python");
    }
    if name.starts_with("nodejs") || name.starts_with("node-") {
        return Some("nodejs");
    }
    if name.starts_with("openjdk-") || name.starts_with("java-") {
        return Some("openjdk");
    }
    if name.starts_with("ruby") && !name.contains("rails") {
        return Some("ruby");
    }
    if name.starts_with("php") {
        return Some("php");
    }
    if name.starts_with("golang") || name == "go" {
        return Some("go");
    }
    if name.starts_with("dotnet") {
        return Some("dotnet");
    }
    if name.starts_with("erlang") {
        return Some("erlang");
    }
    if name.starts_with("elixir") {
        return Some("elixir");
    }
    if name.starts_with("mongodb") || name == "mongod" {
        return Some("mongodb");
    }
    if name.starts_with("elasticsearch") {
        return Some("elasticsearch");
    }

    None
}

/// Detect if a component IS a runtime by ecosystem + name.
fn detect_runtime(ecosystem: &str, name: &str) -> Option<&'static str> {
    let lower_eco = ecosystem.to_lowercase();
    let lower_name = name.to_lowercase();

    match (lower_eco.as_str(), lower_name.as_str()) {
        ("pypi" | "pip", "python" | "cpython") => Some("python"),
        ("npm" | "node", "node" | "nodejs" | "node.js") => Some("nodejs"),
        ("cargo" | "crates.io", "rust" | "rustc") => Some("rust"),
        ("gem" | "rubygems", "ruby") => Some("ruby"),
        ("nuget" | ".net", "dotnet" | ".net") => Some("dotnet"),
        ("go" | "golang", "go" | "golang") => Some("go"),
        ("maven" | "gradle", "java" | "openjdk" | "jdk") => Some("openjdk"),
        ("composer" | "packagist", "php") => Some("php"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_purl_type_name() {
        assert_eq!(
            parse_purl_type_name("pkg:pypi/django@4.2.0"),
            Some(("pypi".to_string(), "django".to_string()))
        );
        assert_eq!(
            parse_purl_type_name("pkg:npm/%40angular/core@16.0.0"),
            Some(("npm".to_string(), "%40angular/core".to_string()))
        );
        assert_eq!(
            parse_purl_type_name("pkg:cargo/tokio@1.35.0"),
            Some(("cargo".to_string(), "tokio".to_string()))
        );
        assert_eq!(parse_purl_type_name("invalid"), None);
        assert_eq!(parse_purl_type_name("pkg:"), None);
    }

    #[test]
    fn test_static_purl_to_product() {
        assert_eq!(
            static_purl_to_product("pypi", "django"),
            Some("django")
        );
        assert_eq!(
            static_purl_to_product("npm", "@angular/core"),
            Some("angular")
        );
        assert_eq!(
            static_purl_to_product("cargo", "tokio"),
            Some("tokio")
        );
        assert_eq!(
            static_purl_to_product("deb", "postgresql-15"),
            Some("postgresql")
        );
        assert_eq!(
            static_purl_to_product("rpm", "nginx"),
            Some("nginx")
        );
        assert_eq!(
            static_purl_to_product("pypi", "unknown-package"),
            None
        );
    }

    #[test]
    fn test_static_system_package() {
        assert_eq!(static_system_package("nginx"), Some("nginx"));
        assert_eq!(static_system_package("python3.11"), Some("python"));
        assert_eq!(static_system_package("openjdk-17-jre"), Some("openjdk"));
        assert_eq!(static_system_package("unknown-pkg"), None);
    }

    #[test]
    fn test_detect_runtime() {
        assert_eq!(detect_runtime("PyPI", "Python"), Some("python"));
        assert_eq!(detect_runtime("npm", "nodejs"), Some("nodejs"));
        assert_eq!(detect_runtime("cargo", "rust"), Some("rust"));
        assert_eq!(detect_runtime("pypi", "django"), None);
    }

    #[test]
    fn test_fuzzy_match_product() {
        let mapper = ProductMapper::new(vec![
            "django".to_string(),
            "redis".to_string(),
            "nginx".to_string(),
        ]);

        // Exact case-insensitive match
        assert_eq!(mapper.fuzzy_match_product("Django"), Some("django".to_string()));
        assert_eq!(mapper.fuzzy_match_product("NGINX"), Some("nginx".to_string()));

        // Suffix stripping
        assert_eq!(
            mapper.fuzzy_match_product("redis-server"),
            Some("redis".to_string())
        );

        // No match — conservative
        assert_eq!(mapper.fuzzy_match_product("unknown"), None);
    }

    #[test]
    fn test_resolve_with_purl() {
        let mapper = ProductMapper::new(vec![]);
        let comp = Component::new("Django".to_string(), "django-id".to_string())
            .with_purl("pkg:pypi/django@4.2.0".to_string())
            .with_version("4.2.0".to_string());

        let resolved = mapper.resolve(&comp);
        assert!(resolved.is_some());
        let r = resolved.unwrap();
        assert_eq!(r.product, "django");
        assert_eq!(r.version, "4.2.0");
    }
}
