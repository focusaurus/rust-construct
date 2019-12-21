#[derive(Debug)]
enum NomError {
    Failed1(String),
    Failed2(String),
}

// models nom_pem::decode_block
fn decode_block(input: &str) -> Result<String, NomError> {
    Ok(input.to_uppercase())
}

#[derive(Debug)]
enum ParseError {
    Bummer(String),
}

// models x509_parser::x509_parser
fn x509_parser(data: String) -> Result<char, ParseError> {
    Ok(data.chars().nth(0).unwrap_or('Z'))
}

fn main() {
    println!("construct");
    let tm_vec = vec![0, 1];
    let second: Result<&u8, &str> = tm_vec.iter().nth(1).ok_or_else(||"nope");
    println!("{:?}", second);
}
