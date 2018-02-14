
#[derive(Debug)]
enum NomError {
    Failed1(String),
    Failed2(String)
}

// models nom_pem::decode_block
fn decode_block(input: &str) -> Result<String, NomError> {
    Ok(input.to_uppercase())
}

#[derive(Debug)]
enum ParseError {
    Bummer(String)
}

// models x509_parser::x509_parser
fn x509_parser(data: String) -> Result<char, ParseError> {
    Ok(data.chars().nth(0).unwrap_or('Z'))
}

fn main() {
    println!("construct");
    println!(
        "{:?}",
        decode_block("hey")
            .map(|upper| x509_parser(upper))
            .map(|a_char| 'X')
            .map_err(|nom_error| format!("{:?}", nom_error))
            // .and_then(|a_char| a_char)
    );
}
