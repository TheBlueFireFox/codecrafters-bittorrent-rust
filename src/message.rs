use std::collections::BTreeMap;

use bytes::{Buf, BufMut};

use crate::bencode;

#[derive(Debug, Clone)]
pub enum Message {
    Choke,
    Unchoke,
    Interested,
    Have(Have),
    BitField(BitField),
    Request(Request),
    Piece(Piece),
    Extension(Extension),
}

impl Message {
    pub fn read(buf: &[u8]) -> Self {
        let len = buf.len();
        let buf = &mut std::io::Cursor::new(buf);

        let length = buf.get_u32();

        let mut buf = (buf as &mut dyn Buf).take(length as usize);
        let m_type = buf.get_u8();

        let r = match m_type {
            0x00 => Self::Choke,
            0x01 => Self::Unchoke,
            0x02 => Self::Interested,
            0x04 => Self::Have(Have::read(&mut buf)),
            0x05 => Self::BitField(BitField::read(&mut buf)),
            0x06 => Self::Request(Request::read(&mut buf)),
            0x07 => Self::Piece(Piece::read(&mut buf)),
            0x14 => Self::Extension(Extension::read(&mut buf)),
            _ => unimplemented!("no a supported message type"),
        };

        assert_eq!(length as usize + 4, len - buf.remaining(), "for {:?}", r);

        r
    }

    pub fn write(&self, buf: &mut Vec<u8>) {
        buf.clear();
        let s = self.inner_writer(buf);
        (&mut buf[..4]).put_u32(s as _);
    }

    fn inner_writer(&self, buf: &mut dyn bytes::BufMut) -> usize {
        let len = buf.remaining_mut();
        // saving space for the size
        buf.put_u32(0);

        match self {
            Message::Choke => buf.put_u8(0x00),
            Message::Unchoke => buf.put_u8(0x01),
            Message::Interested => buf.put_u8(0x02),
            Message::Have(have) => {
                buf.put_u8(0x04);
                have.write(buf);
            }
            Message::BitField(bit_field) => {
                buf.put_u8(0x05);
                bit_field.write(buf);
            }
            Message::Request(request) => {
                // The message id for request is 6
                buf.put_u8(0x06);
                request.write(buf);
            }
            Message::Piece(piece) => {
                // The message id for request is 6
                buf.put_u8(0x07);
                piece.write(buf);
            }
            Message::Extension(ext) => {
                buf.put_u8(0x14);
                ext.write(buf);
            }
        }

        len - buf.remaining_mut() - 4
    }
}

#[derive(Debug, Clone)]
pub struct Have {
    pub index: u32,
}

impl Have {
    fn write(&self, buf: &mut dyn bytes::BufMut) {
        // index: the zero-based piece index
        buf.put_u32(self.index);
    }

    fn read(_buf: &mut dyn Buf) -> Self {
        unimplemented!("why do we get a have message from the peer?");
    }
}

#[derive(Debug, Clone)]
pub struct BitField {
    pub pieces: Vec<u8>,
}

impl BitField {
    fn write(&self, _buf: &mut dyn bytes::BufMut) {
        unimplemented!("why are we sending a bitfield to the peer?");
    }

    fn read(buf: &mut dyn Buf) -> Self {
        let mut pieces = vec![0; buf.remaining()];
        buf.copy_to_slice(&mut pieces);
        Self { pieces }
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub index: u32,
    pub offset: u32,
    pub length: u32,
}

impl Request {
    fn write(&self, buf: &mut dyn bytes::BufMut) {
        // index: the zero-based piece index
        buf.put_u32(self.index);
        // begin: the zero-based byte offset within the piece
        buf.put_u32(self.offset);
        // length: the length of the block in bytes
        buf.put_u32(self.length);
    }

    fn read(_buf: &mut dyn Buf) -> Self {
        unimplemented!("why do we get a request message from the peer?");
    }
}

#[derive(Debug, Clone)]
pub struct Piece {
    pub index: u32,
    pub offset: u32,
    pub piece: Vec<u8>,
}

impl Piece {
    fn write(&self, _buf: &mut dyn bytes::BufMut) {
        unimplemented!("why do we write a piece message to the peer?");
    }

    fn read(buf: &mut dyn Buf) -> Self {
        // index: the zero-based piece index
        let index = buf.get_u32();
        // begin: the zero-based byte offset within the piece
        let offset = buf.get_u32();

        let mut piece = vec![0; buf.remaining()];
        buf.copy_to_slice(&mut piece);

        Self {
            index,
            offset,
            piece,
        }
    }
}


#[derive(Debug, Clone)]
pub struct Extension {
    pub extention_id: BTreeMap<String, i64>,
}

impl Extension {
    fn write(&self, buf: &mut dyn bytes::BufMut) {
        let mut inner = bencode::Mapping::new();
        for (k, v) in &self.extention_id {
            inner.insert(k.clone(), bencode::Value::Int(*v));
        }
        let mut m = bencode::Mapping::new();
        let inner = bencode::Value::Dict(inner);

        m.insert("m".to_string(), inner);

        let m = bencode::Value::Dict(m);

        buf.put_u8(0);

        let v = bencode::encode(&m);
        buf.put_slice(&v);
    }

    fn read(buf: &mut dyn Buf) -> Self {
        let extension_msg_id = buf.get_u8();
        assert_eq!(extension_msg_id, 0);
        let (msg, _) = bencode::decode(buf.chunk());
        buf.advance(buf.remaining());

        // sadly on a rust version that doesn't support if let chaining
        if let bencode::Value::Dict(btree_map) = msg {
            if let bencode::Value::Dict(btree_map) = &btree_map["m"] {
                let mut map = BTreeMap::new();
                for (k, v) in btree_map {
                    if let bencode::Value::Int(v) = v {
                        map.insert(k.clone(), *v);
                    }
                }
                return Self { extention_id: map };
            }
        }

        panic!("Unexpected extension dictionary format");
    }
}
