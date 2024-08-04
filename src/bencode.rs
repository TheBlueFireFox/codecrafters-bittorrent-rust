use core::panic;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bytes(Vec<u8>),
    Int(i64),
    List(Vec<Value>),
    Dict(Mapping),
}

pub type Mapping = BTreeMap<String, Value>;

fn decode_bytes(encoded_value: &[u8]) -> (Value, &[u8]) {
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
    let mut dict = Mapping::new();
    let mut l = &encoded_value[1..];
    loop {
        if l[0] == b'e' {
            break;
        }
        let (k, r) = decode(l);
        let k = if let Value::Bytes(b) = k {
            std::str::from_utf8(&b)
                .expect("unable to cast to string")
                .to_string()
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
        [b'0'..=b'9', ..] => decode_bytes(encoded_value),
        _ => {
            unimplemented!("missing")
        }
    }
}

pub fn format_helper(curr: &Value) -> String {
    match curr {
        Value::Bytes(b) => {
            let s = match std::str::from_utf8(b) {
                Ok(v) => v.to_string(),
                Err(_) => format!("{:?}", b),
            };
            format!("\"{}\"", s,)
        }
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
                    .map(|(k, v)| format!("\"{}\":{}", k, format_helper(v)))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

pub fn extract_dict(value: &Value) -> &Mapping {
    if let Value::Dict(d) = value {
        d
    } else {
        panic!("cannot extract dict from Value")
    }
}

pub fn extract_int(value: &Value) -> &i64 {
    if let Value::Int(d) = value {
        d
    } else {
        panic!("cannot extract int from Value")
    }
}

pub fn extract_bytes(value: &Value) -> &Vec<u8> {
    if let Value::Bytes(l) = value {
        l
    } else {
        panic!("cannot extract int from Value <{:?}>", value)
    }
}

pub fn encode(v: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_inner(v, &mut buf);
    buf
}

fn encode_inner(v: &Value, buf: &mut Vec<u8>) {
    match v {
        Value::Bytes(b) => encode_bytes(b, buf),
        Value::Int(i) => encode_int(*i, buf),
        Value::List(l) => encode_list(l, buf),
        Value::Dict(d) => encode_dict(d, buf),
    }
}

fn encode_dict(value: &Mapping, buf: &mut Vec<u8>) {
    buf.push(b'd');
    for (k, v) in value {
        let k = k.as_bytes();
        encode_bytes(k, buf);
        encode_inner(v, buf);
    }
    buf.push(b'e');
}

fn encode_list(value: &[Value], buf: &mut Vec<u8>) {
    buf.push(b'l');
    for v in value {
        encode_inner(v, buf);
    }
    buf.push(b'e');
}

fn encode_int(value: i64, buf: &mut Vec<u8>) {
    buf.extend_from_slice(format!("i{}e", value).as_bytes());
}

fn encode_bytes(value: &[u8], buf: &mut Vec<u8>) {
    buf.extend_from_slice(format!("{}", value.len()).as_bytes());
    buf.push(b':');
    buf.extend_from_slice(value);
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_decode_bytes() {
        let b = "5:hello".as_bytes();
        let (v, r) = decode(b);
        assert!(r.is_empty());
        assert_eq!(v, Value::Bytes("hello".as_bytes().to_vec()));
    }

    #[test]
    fn test_decode_int() {
        let i = "i52e".as_bytes();
        let (v, r) = decode(i);
        assert!(r.is_empty());
        assert_eq!(v, Value::Int(52));

        let b = "i-52e".as_bytes();
        let (v, r) = decode(b);
        assert!(r.is_empty());
        assert_eq!(v, Value::Int(-52));
    }

    #[test]
    fn test_decode_list() {
        let l = "l5:helloi52ee".as_bytes();
        let (v, r) = decode(l);
        assert!(r.is_empty());
        assert_eq!(
            v,
            Value::List(vec![
                Value::Bytes("hello".as_bytes().to_vec()),
                Value::Int(52)
            ])
        );
    }

    #[test]
    fn test_decode_dict() {
        let d = "d3:foo3:bar5:helloi52ee".as_bytes();
        let (v, r) = decode(d);
        assert!(r.is_empty());
        let mut d = Mapping::new();
        d.insert("foo".to_string(), Value::Bytes("bar".as_bytes().to_vec()));
        d.insert("hello".to_string(), Value::Int(52));

        assert_eq!(v, Value::Dict(d));
    }

    #[test]
    fn test_encode_bytes() {
        let input = Value::Bytes("hello".as_bytes().to_vec());
        let b = "5:hello".as_bytes();
        let v = encode(&input);
        assert_eq!(b, &v);
    }

    #[test]
    fn test_encode_int() {
        let val = Value::Int(52);
        let i = "i52e".as_bytes();
        let v = encode(&val);
        assert_eq!(v, i);

        let val = Value::Int(-52);
        let i = "i-52e".as_bytes();
        let v = encode(&val);
        assert_eq!(v, i);
    }

    #[test]
    fn test_encode_list() {
        let inp = Value::List(vec![
            Value::Bytes("hello".as_bytes().to_vec()),
            Value::Int(52),
        ]);
        let l = "l5:helloi52ee".as_bytes();
        let v = encode(&inp);
        assert_eq!(v, l);
    }

    #[test]
    fn test_encode_dict() {
        let mut d = Mapping::new();
        d.insert("foo".to_string(), Value::Bytes("bar".as_bytes().to_vec()));
        d.insert("hello".to_string(), Value::Int(52));
        let d = Value::Dict(d);
        let inp = "d3:foo3:bar5:helloi52ee";
        let v = encode(&d);
        let v = std::str::from_utf8(&v).unwrap();

        assert_eq!(v, inp);
    }
}
