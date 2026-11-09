//! Minimal Java Object Serialization (stream protocol v5) support, just enough to read and write
//! the `SealedObjectForKeyProtector` / `SecretKeySpec` objects JCEKS uses for secret key entries.

use crate::util::Res;
use std::collections::HashMap;

const MAGIC: u16 = 0xACED;
const VERSION: u16 = 5;
const TC_NULL: u8 = 0x70;
const TC_REFERENCE: u8 = 0x71;
const TC_CLASSDESC: u8 = 0x72;
const TC_OBJECT: u8 = 0x73;
const TC_STRING: u8 = 0x74;
const TC_ARRAY: u8 = 0x75;
const TC_CLASS: u8 = 0x76;
const TC_BLOCKDATA: u8 = 0x77;
const TC_ENDBLOCKDATA: u8 = 0x78;
const TC_LONGSTRING: u8 = 0x7C;
const TC_ENUM: u8 = 0x7E;
const TC_BLOCKDATALONG: u8 = 0x7A;
const BASE_HANDLE: u32 = 0x7E_0000;
const SC_WRITE_METHOD: u8 = 0x01;

#[derive(Clone, Debug)]
pub struct ClassDesc {
    pub name: String,
    flags: u8,
    fields: Vec<(u8, String)>,
    superclass: Option<Box<ClassDesc>>,
}

#[derive(Clone, Debug)]
pub enum JValue {
    Null,
    Prim(i64),
    Str(String),
    Bytes(Vec<u8>),
    Array(Vec<JValue>),
    Object { class: String, fields: HashMap<String, JValue> },
    Enum { constant: String },
    Class(Box<ClassDesc>),
}

impl JValue {
    pub fn field(&self, name: &str) -> Option<&JValue> {
        match self {
            JValue::Object { fields, .. } => fields.get(name),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            JValue::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn class(&self) -> Option<&str> {
        match self {
            JValue::Object { class, .. } => Some(class),
            _ => None,
        }
    }
}

#[derive(Clone)]
enum Handle {
    Desc(Box<ClassDesc>),
    Value(JValue),
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    handles: Vec<Handle>,
}

fn bad() -> String {
    "corrupt Java serialized object in keystore".to_string()
}

impl<'a> Reader<'a> {
    /// Starts reading a stream at `data`; returns the reader so the caller can learn how many
    /// bytes the object occupied (JCEKS stores objects without a length prefix).
    pub fn new(data: &'a [u8]) -> Res<Self> {
        let mut r = Reader { data, pos: 0, handles: Vec::new() };
        if r.u16()? != MAGIC || r.u16()? != VERSION {
            return Err("not a Java serialization stream".into());
        }
        Ok(r)
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.data.len()).ok_or_else(bad)?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Res<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Res<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn utf(&mut self) -> Res<String> {
        let len = self.u16()? as usize;
        Ok(String::from_utf8_lossy(self.take(len)?).to_string())
    }
    fn peek(&self) -> Res<u8> {
        self.data.get(self.pos).copied().ok_or_else(bad)
    }

    fn handle(&mut self) -> Res<Handle> {
        let idx = self.u32()?.checked_sub(BASE_HANDLE).ok_or_else(bad)? as usize;
        self.handles.get(idx).cloned().ok_or_else(bad)
    }

    fn class_desc(&mut self) -> Res<Option<Box<ClassDesc>>> {
        match self.u8()? {
            TC_NULL => Ok(None),
            TC_REFERENCE => match self.handle()? {
                Handle::Desc(d) => Ok(Some(d)),
                _ => Err(bad()),
            },
            TC_CLASSDESC => {
                let name = self.utf()?;
                let _uid = self.take(8)?;
                let slot = self.handles.len();
                self.handles.push(Handle::Value(JValue::Null));
                let flags = self.u8()?;
                let count = self.u16()?;
                let mut fields = Vec::new();
                for _ in 0..count {
                    let code = self.u8()?;
                    let fname = self.utf()?;
                    if code == b'[' || code == b'L' {
                        self.object()?; // class name string
                    }
                    fields.push((code, fname));
                }
                self.skip_annotation()?;
                let superclass = self.class_desc()?;
                let desc = Box::new(ClassDesc { name, flags, fields, superclass });
                self.handles[slot] = Handle::Desc(desc.clone());
                Ok(Some(desc))
            }
            _ => Err(bad()),
        }
    }

    fn skip_annotation(&mut self) -> Res<()> {
        loop {
            match self.peek()? {
                TC_ENDBLOCKDATA => {
                    self.pos += 1;
                    return Ok(());
                }
                TC_BLOCKDATA => {
                    self.pos += 1;
                    let n = self.u8()? as usize;
                    self.take(n)?;
                }
                TC_BLOCKDATALONG => {
                    self.pos += 1;
                    let n = self.u32()? as usize;
                    self.take(n)?;
                }
                _ => {
                    self.object()?;
                }
            }
        }
    }

    fn prim(&mut self, code: u8) -> Res<i64> {
        Ok(match code {
            b'B' | b'Z' => self.u8()? as i8 as i64,
            b'C' | b'S' => self.u16()? as i16 as i64,
            b'I' | b'F' => self.u32()? as i32 as i64,
            b'J' | b'D' => i64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            _ => return Err(bad()),
        })
    }

    /// Reads one object (any content element).
    pub fn object(&mut self) -> Res<JValue> {
        match self.peek()? {
            TC_NULL => {
                self.pos += 1;
                Ok(JValue::Null)
            }
            TC_REFERENCE => {
                self.pos += 1;
                match self.handle()? {
                    Handle::Value(v) => Ok(v),
                    Handle::Desc(d) => Ok(JValue::Class(d)),
                }
            }
            TC_STRING => {
                self.pos += 1;
                let s = JValue::Str(self.utf()?);
                self.handles.push(Handle::Value(s.clone()));
                Ok(s)
            }
            TC_LONGSTRING => {
                self.pos += 1;
                let len = u64::from_be_bytes(self.take(8)?.try_into().unwrap()) as usize;
                let s = JValue::Str(String::from_utf8_lossy(self.take(len)?).to_string());
                self.handles.push(Handle::Value(s.clone()));
                Ok(s)
            }
            TC_CLASSDESC => Ok(JValue::Class(self.class_desc()?.ok_or_else(bad)?)),
            TC_CLASS => {
                self.pos += 1;
                let d = self.class_desc()?.ok_or_else(bad)?;
                self.handles.push(Handle::Value(JValue::Class(d.clone())));
                Ok(JValue::Class(d))
            }
            TC_ARRAY => {
                self.pos += 1;
                let desc = self.class_desc()?.ok_or_else(bad)?;
                let slot = self.handles.len();
                self.handles.push(Handle::Value(JValue::Null));
                let len = self.u32()? as usize;
                let elem = desc.name.as_bytes().get(1).copied().ok_or_else(bad)?;
                let value = if elem == b'B' {
                    JValue::Bytes(self.take(len)?.to_vec())
                } else if elem == b'L' || elem == b'[' {
                    JValue::Array((0..len).map(|_| self.object()).collect::<Res<_>>()?)
                } else {
                    JValue::Array((0..len).map(|_| self.prim(elem).map(JValue::Prim)).collect::<Res<_>>()?)
                };
                self.handles[slot] = Handle::Value(value.clone());
                Ok(value)
            }
            TC_ENUM => {
                self.pos += 1;
                let _desc = self.class_desc()?;
                let slot = self.handles.len();
                self.handles.push(Handle::Value(JValue::Null));
                let constant = self.object()?.as_str().unwrap_or_default().to_string();
                let v = JValue::Enum { constant };
                self.handles[slot] = Handle::Value(v.clone());
                Ok(v)
            }
            TC_OBJECT => {
                self.pos += 1;
                let desc = self.class_desc()?.ok_or_else(bad)?;
                let slot = self.handles.len();
                self.handles.push(Handle::Value(JValue::Null));
                // Class data is written superclass first.
                let mut chain = Vec::new();
                let mut cur = Some(desc.clone());
                while let Some(d) = cur {
                    cur = d.superclass.clone();
                    chain.push(d);
                }
                let mut fields = HashMap::new();
                for d in chain.iter().rev() {
                    for (code, name) in &d.fields {
                        let v = if *code == b'[' || *code == b'L' { self.object()? } else { JValue::Prim(self.prim(*code)?) };
                        fields.insert(name.clone(), v);
                    }
                    if d.flags & SC_WRITE_METHOD != 0 {
                        self.skip_annotation()?;
                    }
                }
                let v = JValue::Object { class: desc.name.clone(), fields };
                self.handles[slot] = Handle::Value(v.clone());
                Ok(v)
            }
            _ => Err(bad()),
        }
    }
}

/// Parses a complete serialization stream and returns its first object.
pub fn parse(data: &[u8]) -> Res<JValue> {
    Reader::new(data)?.object()
}

// ---------------------------------------------------------------------------------------------
// Writers for the two object graphs JCEKS needs
// ---------------------------------------------------------------------------------------------

fn put_utf(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

const UID_SEALED_OBJECT_FOR_KEY_PROTECTOR: u64 = 0xCD57_CA59_E730_BB53;
const UID_SEALED_OBJECT: u64 = 0x3E36_3DA6_C3B7_5470;
const UID_BYTE_ARRAY: u64 = 0xACF3_17F8_0608_54E0;
const UID_SECRET_KEY_SPEC: u64 = 0x5B47_0B66_E230_2619;

/// Serialized `javax.crypto.spec.SecretKeySpec(key, algorithm)`.
pub fn write_secret_key_spec(algorithm: &str, key: &[u8]) -> Vec<u8> {
    let mut o = vec![0xAC, 0xED, 0x00, 0x05, TC_OBJECT, TC_CLASSDESC];
    put_utf(&mut o, "javax.crypto.spec.SecretKeySpec"); // handle 0
    o.extend_from_slice(&UID_SECRET_KEY_SPEC.to_be_bytes());
    o.push(0x02);
    o.extend_from_slice(&2u16.to_be_bytes());
    o.push(b'L');
    put_utf(&mut o, "algorithm");
    o.push(TC_STRING); // handle 1
    put_utf(&mut o, "Ljava/lang/String;");
    o.push(b'[');
    put_utf(&mut o, "key");
    o.push(TC_STRING); // handle 2
    put_utf(&mut o, "[B");
    o.extend_from_slice(&[TC_ENDBLOCKDATA, TC_NULL]);
    // object = handle 3; values in field order
    o.push(TC_STRING); // handle 4
    put_utf(&mut o, algorithm);
    o.extend_from_slice(&[TC_ARRAY, TC_CLASSDESC]);
    put_utf(&mut o, "[B"); // handle 5
    o.extend_from_slice(&UID_BYTE_ARRAY.to_be_bytes());
    o.extend_from_slice(&[0x02, 0x00, 0x00, TC_ENDBLOCKDATA, TC_NULL]);
    o.extend_from_slice(&(key.len() as u32).to_be_bytes()); // array handle 6
    o.extend_from_slice(key);
    o
}

/// Serialized `com.sun.crypto.provider.SealedObjectForKeyProtector` as written by JceKeyStore.
pub fn write_sealed_object(encoded_params: &[u8], encrypted_content: &[u8], alg: &str) -> Vec<u8> {
    let mut o = vec![0xAC, 0xED, 0x00, 0x05, TC_OBJECT, TC_CLASSDESC];
    put_utf(&mut o, "com.sun.crypto.provider.SealedObjectForKeyProtector"); // handle 0
    o.extend_from_slice(&UID_SEALED_OBJECT_FOR_KEY_PROTECTOR.to_be_bytes());
    o.extend_from_slice(&[0x02, 0x00, 0x00, TC_ENDBLOCKDATA, TC_CLASSDESC]);
    put_utf(&mut o, "javax.crypto.SealedObject"); // handle 1
    o.extend_from_slice(&UID_SEALED_OBJECT.to_be_bytes());
    o.push(0x02);
    o.extend_from_slice(&4u16.to_be_bytes());
    o.push(b'[');
    put_utf(&mut o, "encodedParams");
    o.push(TC_STRING); // handle 2
    put_utf(&mut o, "[B");
    o.push(b'[');
    put_utf(&mut o, "encryptedContent");
    o.extend_from_slice(&[TC_REFERENCE, 0x00, 0x7E, 0x00, 0x02]);
    o.push(b'L');
    put_utf(&mut o, "paramsAlg");
    o.push(TC_STRING); // handle 3
    put_utf(&mut o, "Ljava/lang/String;");
    o.push(b'L');
    put_utf(&mut o, "sealAlg");
    o.extend_from_slice(&[TC_REFERENCE, 0x00, 0x7E, 0x00, 0x03]);
    o.extend_from_slice(&[TC_ENDBLOCKDATA, TC_NULL]);
    // object = handle 4
    o.extend_from_slice(&[TC_ARRAY, TC_CLASSDESC]);
    put_utf(&mut o, "[B"); // handle 5
    o.extend_from_slice(&UID_BYTE_ARRAY.to_be_bytes());
    o.extend_from_slice(&[0x02, 0x00, 0x00, TC_ENDBLOCKDATA, TC_NULL]);
    o.extend_from_slice(&(encoded_params.len() as u32).to_be_bytes()); // handle 6
    o.extend_from_slice(encoded_params);
    o.extend_from_slice(&[TC_ARRAY, TC_REFERENCE, 0x00, 0x7E, 0x00, 0x05]);
    o.extend_from_slice(&(encrypted_content.len() as u32).to_be_bytes()); // handle 7
    o.extend_from_slice(encrypted_content);
    o.push(TC_STRING); // handle 8
    put_utf(&mut o, alg);
    o.extend_from_slice(&[TC_REFERENCE, 0x00, 0x7E, 0x00, 0x08]);
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_object_round_trips() {
        let bytes = write_sealed_object(&[1, 2, 3], &[9; 32], "PBEWithMD5AndTripleDES");
        let mut r = Reader::new(&bytes).unwrap();
        let v = r.object().unwrap();
        assert_eq!(r.position(), bytes.len());
        assert_eq!(v.class(), Some("com.sun.crypto.provider.SealedObjectForKeyProtector"));
        assert_eq!(v.field("encodedParams").unwrap().as_bytes().unwrap(), &[1, 2, 3]);
        assert_eq!(v.field("encryptedContent").unwrap().as_bytes().unwrap(), &[9; 32]);
        assert_eq!(v.field("sealAlg").unwrap().as_str().unwrap(), "PBEWithMD5AndTripleDES");
    }

    #[test]
    fn secret_key_spec_round_trips() {
        let bytes = write_secret_key_spec("AES", &[7; 16]);
        let v = parse(&bytes).unwrap();
        assert_eq!(v.field("algorithm").unwrap().as_str(), Some("AES"));
        assert_eq!(v.field("key").unwrap().as_bytes().unwrap(), &[7; 16]);
    }
}
