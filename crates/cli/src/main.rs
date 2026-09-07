//! `fz` standalone binary. The real `fz` runs inside a venture repo where
//! it links against the venture's harness (see the library docs). This
//! standalone build can only explain that.

#![forbid(unsafe_code)]

fn main() {
    eprintln!(
        "fz must run inside a venture: add the [[bin]] target that calls \
         cratefield_cli::main_for(your::harness) — see \
         https://github.com/Cratefield/harness (cratefield-cli README)."
    );
    std::process::exit(2);
}
