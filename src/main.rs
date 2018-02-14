#![feature(rich_main_return)]
#![feature(try_trait)]
extern crate base64;
extern crate der_parser;
extern crate nom;
extern crate time;
extern crate x509_parser;

use std::fmt;
use nom::IResult;
use x509_parser::X509Certificate;
use x509_parser::TbsCertificate;
// use x509_parser::error::X509Error;
// use der_parser::DerObjectContent;
use std::error::Error;

const X509: &str = "
MIIDdDCCAlwCCQDkDZkrZ825JzANBgkqhkiG9w0BAQUFADB8MQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQUwxEjAQBgNVBAcMCUZhaXJiYW5rczEeMBwGA1UECgwVVGVh
bGVhdmVzIERldmVsb3BtZW50MRIwEAYDVQQLDAlUZWFsZWF2ZXMxGDAWBgNVBAMM
D3RlYWxlYXZlcy5sb2NhbDAeFw0xODAxMDkyMzIyMzJaFw0yMzAxMDgyMzIyMzJa
MHwxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJBTDESMBAGA1UEBwwJRmFpcmJhbmtz
MR4wHAYDVQQKDBVUZWFsZWF2ZXMgRGV2ZWxvcG1lbnQxEjAQBgNVBAsMCVRlYWxl
YXZlczEYMBYGA1UEAwwPdGVhbGVhdmVzLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwwVVgSs70hYVf94hohwNG1QhY4TOY6s+fArJSKuToL4c
+wqUX17/RE4BRMjhZYyr+TUN7qZowrS2Sa7e4m/iFHtcFUIKcssGGch5cON+ClSL
2aUWFvDU5NmZT26swKR7LmkYTHjE0poP/VpYSucpaogCSsgTM4LMlsMaeN9aNynd
M++53RSkXypNXSFTTMESmpUT9kTJymtVdUBDoP2hJT8BoAfaR2PeuOrNp/FEsgkX
fPWxy4OCdD7/X6+wOQCCHFZwb3iMHLL+78yEwk9MsTMQK0veVOh40EGtGP1Agg+M
GgbMPmM2Yd3dhXw4PdbfnGW+0p54LsuGaTs9p/bNPwIDAQABMA0GCSqGSIb3DQEB
BQUAA4IBAQAx/ZYP9gHX0NsnUI7S9Tiov1zqJZz/t3V0jh46mUdiqMh03yRU4q95
vKgvFmo7WdGsgnO0xFw+zi54pkbz9dH8jO9pqUsF+2+X7BqkwxNvIl5EkIZUHncE
S316HKhgFEccbfGiqd8CTVIflchV+es8hE/ZADplmjgcWd7h+d+1PFq92e4dAXOK
hbWpyrRTqkXBOuwf2HGS4MetgkRK3Bx4b7t6jVfyE24Chjz/xyELTJjJKx2doLp1
kBWdwgoVtFAqYblMgj9PooTHQE74mFqoHxo3bGcIIjyrL/CuEj7u9FRrh9LkUjX3
ofaybcIL5W4mqqWgirIMyZYaIjv36b0h
";

struct Certificate<'a> {
    pub cert_bytes: &'a [u8],
    pub xcert: &'a X509Certificate<'a>,
    // pub tbs: TbsCertificate<'a>,
    pub expires: time::Tm,
}

struct TeaError {
    pub message: String,
}

impl From<base64::DecodeError> for TeaError {
    fn from(err: base64::DecodeError) -> TeaError {
        TeaError {
            message: err.description().into(),
        }
    }
}
impl From<String> for TeaError {
    fn from(message: String) -> TeaError {
        TeaError { message }
    }
}

impl From<x509_parser::error::X509Error> for TeaError {
    fn from(error: x509_parser::error::X509Error) -> TeaError {
        TeaError {
            message: format!("{:?}", error),
        }
    }
}

impl From<std::option::NoneError> for TeaError {
    fn from(_error: std::option::NoneError) -> TeaError {
        TeaError {
            message: "Invalid Validity (need 2 dates)".into(),
        }
    }
}

impl fmt::Display for TeaError {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        write!(out, "{}", self.message)
    }
}

fn parse_certificate4(
    x509_bytes: &[u8],
) -> Result<x509_parser::X509Certificate, String> {
    match x509_parser::x509_parser(x509_bytes) {
        IResult::Done(_unparsed_suffix, xcert) => Ok(xcert),
        IResult::Error(error) => Err(format!("{}", error)),
        IResult::Incomplete(needed) => Err(format!("Incomplete parse: {:?}", needed)),
    }
}

fn decode(pretty_base64: &str) -> Result<Vec<u8>, TeaError> {
    let clean_base64: String = pretty_base64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    Ok(base64::decode(&clean_base64)?)
}

fn parse_outer(cert_bytes: &[u8]) -> Result<Certificate, TeaError> {
    // let cert_base64: String = X509.chars().filter(|c| !c.is_whitespace()).collect();
    let xcert = parse_certificate4(cert_bytes)?;
    let tbs = xcert.tbs_certificate()?;
    let validity = tbs.validity()?;
    let expires = validity.iter().nth(1)?;
    // let algo = xcert.signature_algorithm()?;
    Ok(Certificate {
        cert_bytes,
        xcert: &xcert,
        // tbs,
        expires: *expires,
    })
}

// #[allow(unused)]
// fn main2() {
//     match decode(X509) {
//         Ok(cert_bytes) => parse_outer(&cert_bytes).and_then(|cert| {
//             println!("Got CERT, {:?}", cert.xcert.signature_algorithm());
//             Ok(())
//         }),
//         Err(e) => {
//             eprintln!("{}", e);
//             std::process::exit(10);
//         }
//     };
// }

fn main() {
    let cert_bytes = decode(X509).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(10);
    });
    let cert = parse_outer(&cert_bytes).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(10);
    });
    println!("Got expires, {:?}", cert.expires);
    println!("Got bytes, {:?}", &cert.cert_bytes[0..2]);
}
