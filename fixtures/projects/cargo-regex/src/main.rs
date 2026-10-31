use regex::Regex;

fn main() {
    let re = Regex::new(r"^acct-\d{6}$").unwrap();
    println!("{}", re.is_match("acct-123456"));
}
