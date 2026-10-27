fn main() {
    if let Err(e) = escrypter::ecp::main_entry() {
        eprintln!("ESCrypter Agent: {e:#}");
        std::process::exit(1)
    }
}
