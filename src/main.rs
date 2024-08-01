use clap::Parser;

/// Simple program to greet a person
#[derive(clap::Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    Decode(Decode),
}

#[derive(clap::Args, Debug)]
struct Decode {
    /// The path to read from
    bencode: String,
}

mod bencode {
    use core::panic;
    use std::collections::HashMap;

    use serde_bencode::value::Value;

    fn decode_str(encoded_value: &[u8]) -> (Value, &[u8]) {
        let idx = encoded_value
            .iter()
            .position(|&a| a == b':')
            .expect("unable to find ':' in the string");
        let (number, rest) = &encoded_value.split_at(idx);
        let number = std::str::from_utf8(number)
            .expect("able to convert to utf8")
            .parse()
            .expect("able to parse string lenght");
        let (s, rest) = &rest[1..].split_at(number);
        (Value::Bytes(s.to_vec()), rest)
    }

    fn decode_int(encoded_value: &[u8]) -> (Value, &[u8]) {
        let idx = encoded_value
            .iter()
            .position(|&a| a == b'e')
            .expect("unable to find ':' in the string");
        let (v, rest) = encoded_value.split_at(idx + 1);
        // iXXXe => XXX
        let v = &v[1..idx];
        match v {
            [b'0'] => (Value::Int(0), rest),
            [b'-', b'0', ..] => panic!("invalid integer value"),
            [b'0', ..] => panic!("invalid integer value"),
            x => {
                let x = std::str::from_utf8(x)
                    .expect("invalid utf8")
                    .parse()
                    .expect("correct int");
                (Value::Int(x), rest)
            }
        }
    }

    pub fn decode_lst(encoded_value: &[u8]) -> (Value, &[u8]) {
        let mut lst = Vec::new();
        let mut l = &encoded_value[1..];
        loop {
            if l[0] == b'e' {
                break;
            }
            let (v, r) = decode(l);
            l = r;
            lst.push(v);
        }
        (Value::List(lst), &l[1..])
    }

    pub fn decode_dict(encoded_value: &[u8]) -> (Value, &[u8]) {
        let mut dict = HashMap::new();
        let mut l = &encoded_value[1..];
        loop {
            if l[0] == b'e' {
                break;
            }
            let (k, r) = decode(l);
            let k = if let Value::Bytes(b) = k {
                b
            } else {
                panic!("Dict structure incorrect -- key has to be string/bytes");
            };

            l = r;
            let (v, r) = decode(l);
            l = r;

            dict.insert(k, v);
        }

        (Value::Dict(dict), &l[1..])
    }

    pub fn decode(encoded_value: &[u8]) -> (Value, &[u8]) {
        match encoded_value {
            [b'd', b'e', ..] => (Value::Dict(Default::default()), &encoded_value[2..]),
            [b'l', ..] => decode_lst(encoded_value),
            [b'd', ..] => decode_dict(encoded_value),
            [b'i', ..] => decode_int(encoded_value),
            [b'0'..=b'9', ..] => decode_str(encoded_value),
            _ => {
                unimplemented!("missing")
            }
        }
    }

    pub fn format_helper(curr: &Value) -> String {
        match curr {
            Value::Bytes(b) => format!("\"{}\"", std::str::from_utf8(b).expect("incorrect bytes"),),
            Value::Int(i) => format!("{i}"),
            Value::List(l) => {
                format!(
                    "[{}]",
                    l.iter().map(format_helper).collect::<Vec<_>>().join(",")
                )
            }
            Value::Dict(d) => {
                format!(
                    "{{{}}}",
                    d.iter()
                        .map(|(k, v)| format!(
                            "{}:{}",
                            format_helper(&Value::Bytes(k.to_vec())),
                            format_helper(v)
                        ))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            }
        }
    }
}

fn decode(bencode: &[u8]) {
    let (s, _) = bencode::decode(bencode);
    println!("{}", bencode::format_helper(&s));
}

fn main() {
    let args = Args::parse();
    match args.command {
        Commands::Decode(Decode { bencode }) => decode(bencode.as_bytes()),
    }
}
