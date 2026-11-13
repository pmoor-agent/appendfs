//! The encoding used for everything appendfs persists.
//!
//! Encodes and decodes `serde` types using big-endian, fixed-width integers matching the
//! `bincode` 1.x `DefaultOptions::new().with_fixint_encoding().with_big_endian()` wire
//! layout, so on-disk bytes remain identical across versions without depending on an
//! external `bincode` crate.

use serde::de::{DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde::ser::{
    SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple, SerializeTupleStruct,
    SerializeTupleVariant,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Write};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    UnexpectedEof,
    TrailingBytes,
    InvalidBool(u8),
    InvalidOptionTag(u8),
    InvalidUtf8(std::str::Utf8Error),
    InvalidChar,
    SequenceMustHaveLength,
    LengthOverflow,
    DeserializeAnyNotSupported,
    Custom(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "wire I/O error: {}", e),
            Error::UnexpectedEof => write!(f, "unexpected end of wire input"),
            Error::TrailingBytes => write!(f, "unexpected trailing bytes in wire input"),
            Error::InvalidBool(b) => write!(f, "invalid bool byte in wire input: {:#x}", b),
            Error::InvalidOptionTag(b) => write!(f, "invalid option tag in wire input: {:#x}", b),
            Error::InvalidUtf8(e) => write!(f, "invalid UTF-8 in wire input: {}", e),
            Error::InvalidChar => write!(f, "invalid UTF-8 char in wire input"),
            Error::SequenceMustHaveLength => write!(f, "sequences and maps must have a known length"),
            Error::LengthOverflow => write!(f, "wire length exceeds platform usize"),
            Error::DeserializeAnyNotSupported => write!(f, "wire format does not support deserialize_any"),
            Error::Custom(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::InvalidUtf8(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl serde::ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::Custom(msg.to_string())
    }
}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::Custom(msg.to_string())
    }
}

/// Serializes `value` in the on-disk encoding.
pub fn serialize<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    serialize_into(&mut out, value)?;
    Ok(out)
}

/// Serializes `value` directly into `writer` in the on-disk encoding.
pub fn serialize_into<W: Write, T: ?Sized + Serialize>(writer: W, value: &T) -> Result<()> {
    let mut ser = WriterSerializer { writer };
    value.serialize(&mut ser)
}

/// Deserializes `bytes` written by [`serialize`].
pub fn deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    let mut de = SliceDeserializer { input: bytes };
    let value = T::deserialize(&mut de)?;
    if !de.input.is_empty() {
        return Err(Error::TrailingBytes);
    }
    Ok(value)
}

struct WriterSerializer<W: Write> {
    writer: W,
}

impl<W: Write> WriterSerializer<W> {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_all(bytes)?;
        Ok(())
    }

    fn write_len(&mut self, len: usize) -> Result<()> {
        let len = u64::try_from(len).map_err(|_| Error::LengthOverflow)?;
        self.write_all(&len.to_be_bytes())
    }
}

impl<'a, W: Write> serde::Serializer for &'a mut WriterSerializer<W> {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = CompoundSerializer<'a, W>;
    type SerializeTuple = CompoundSerializer<'a, W>;
    type SerializeTupleStruct = CompoundSerializer<'a, W>;
    type SerializeTupleVariant = CompoundSerializer<'a, W>;
    type SerializeMap = CompoundSerializer<'a, W>;
    type SerializeStruct = CompoundSerializer<'a, W>;
    type SerializeStructVariant = CompoundSerializer<'a, W>;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_bool(self, v: bool) -> Result<()> {
        self.write_all(&[u8::from(v)])
    }

    fn serialize_i8(self, v: i8) -> Result<()> {
        self.write_all(&v.to_be_bytes())
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        self.write_all(&v.to_be_bytes())
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        self.write_all(&v.to_be_bytes())
    }

    fn serialize_i64(self, v: i64) -> Result<()> {
        self.write_all(&v.to_be_bytes())
    }

    fn serialize_i128(self, v: i128) -> Result<()> {
        self.write_all(&v.to_be_bytes())
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        self.write_all(&[v])
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        self.write_all(&v.to_be_bytes())
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        self.write_all(&v.to_be_bytes())
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        self.write_all(&v.to_be_bytes())
    }

    fn serialize_u128(self, v: u128) -> Result<()> {
        self.write_all(&v.to_be_bytes())
    }

    fn serialize_f32(self, v: f32) -> Result<()> {
        self.write_all(&v.to_bits().to_be_bytes())
    }

    fn serialize_f64(self, v: f64) -> Result<()> {
        self.write_all(&v.to_bits().to_be_bytes())
    }

    fn serialize_char(self, v: char) -> Result<()> {
        let mut buf = [0u8; 4];
        let encoded = v.encode_utf8(&mut buf);
        self.write_all(encoded.as_bytes())
    }

    fn serialize_str(self, v: &str) -> Result<()> {
        self.serialize_bytes(v.as_bytes())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        self.write_len(v.len())?;
        self.write_all(v)
    }

    fn serialize_none(self) -> Result<()> {
        self.write_all(&[0])
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<()> {
        self.write_all(&[1])?;
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<()> {
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        Ok(())
    }

    fn serialize_unit_variant(self, _name: &'static str, variant_index: u32, _variant: &'static str) -> Result<()> {
        self.serialize_u32(variant_index)
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _name: &'static str, value: &T) -> Result<()> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<()> {
        self.serialize_u32(variant_index)?;
        value.serialize(self)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        let len = len.ok_or(Error::SequenceMustHaveLength)?;
        self.write_len(len)?;
        Ok(CompoundSerializer { ser: self })
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Ok(CompoundSerializer { ser: self })
    }

    fn serialize_tuple_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeTupleStruct> {
        Ok(CompoundSerializer { ser: self })
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.serialize_u32(variant_index)?;
        Ok(CompoundSerializer { ser: self })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        let len = len.ok_or(Error::SequenceMustHaveLength)?;
        self.write_len(len)?;
        Ok(CompoundSerializer { ser: self })
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Ok(CompoundSerializer { ser: self })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.serialize_u32(variant_index)?;
        Ok(CompoundSerializer { ser: self })
    }
}

struct CompoundSerializer<'a, W: Write> {
    ser: &'a mut WriterSerializer<W>,
}

impl<W: Write> SerializeSeq for CompoundSerializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> SerializeTuple for CompoundSerializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> SerializeTupleStruct for CompoundSerializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> SerializeTupleVariant for CompoundSerializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> SerializeMap for CompoundSerializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<()> {
        key.serialize(&mut *self.ser)
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> SerializeStruct for CompoundSerializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, _key: &'static str, value: &T) -> Result<()> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> SerializeStructVariant for CompoundSerializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, _key: &'static str, value: &T) -> Result<()> {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

struct SliceDeserializer<'de> {
    input: &'de [u8],
}

impl<'de> SliceDeserializer<'de> {
    fn read_bytes(&mut self, len: usize) -> Result<&'de [u8]> {
        if self.input.len() < len {
            return Err(Error::UnexpectedEof);
        }
        let (head, tail) = self.input.split_at(len);
        self.input = tail;
        Ok(head)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.read_bytes(N)?;
        Ok(bytes.try_into().unwrap())
    }

    fn read_len(&mut self) -> Result<usize> {
        let len = u64::from_be_bytes(self.read_array()?);
        usize::try_from(len).map_err(|_| Error::LengthOverflow)
    }
}

impl<'de> serde::Deserializer<'de> for &mut SliceDeserializer<'de> {
    type Error = Error;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::DeserializeAnyNotSupported)
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let b = self.read_array::<1>()?[0];
        match b {
            0 => visitor.visit_bool(false),
            1 => visitor.visit_bool(true),
            _ => Err(Error::InvalidBool(b)),
        }
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_i8(i8::from_be_bytes(self.read_array()?))
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_i16(i16::from_be_bytes(self.read_array()?))
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_i32(i32::from_be_bytes(self.read_array()?))
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_i64(i64::from_be_bytes(self.read_array()?))
    }

    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_i128(i128::from_be_bytes(self.read_array()?))
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u8(self.read_array::<1>()?[0])
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u16(u16::from_be_bytes(self.read_array()?))
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u32(u32::from_be_bytes(self.read_array()?))
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u64(u64::from_be_bytes(self.read_array()?))
    }

    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u128(u128::from_be_bytes(self.read_array()?))
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_f32(f32::from_bits(u32::from_be_bytes(self.read_array()?)))
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_f64(f64::from_bits(u64::from_be_bytes(self.read_array()?)))
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let first = self.read_array::<1>()?[0];
        let width = match first {
            0x00..=0x7F => 1,
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => return Err(Error::InvalidChar),
        };
        let mut buf = [first, 0, 0, 0];
        if width > 1 {
            let rest = self.read_bytes(width - 1)?;
            buf[1..width].copy_from_slice(rest);
        }
        let s = std::str::from_utf8(&buf[..width]).map_err(Error::InvalidUtf8)?;
        let ch = s.chars().next().ok_or(Error::InvalidChar)?;
        visitor.visit_char(ch)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.read_len()?;
        let bytes = self.read_bytes(len)?;
        let s = std::str::from_utf8(bytes).map_err(Error::InvalidUtf8)?;
        visitor.visit_borrowed_str(s)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.read_len()?;
        let bytes = self.read_bytes(len)?;
        visitor.visit_borrowed_bytes(bytes)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let tag = self.read_array::<1>()?[0];
        match tag {
            0 => visitor.visit_none(),
            1 => visitor.visit_some(self),
            _ => Err(Error::InvalidOptionTag(tag)),
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.read_len()?;
        visitor.visit_seq(FixedLenReader {
            de: self,
            remaining: len,
        })
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        visitor.visit_seq(FixedLenReader {
            de: self,
            remaining: len,
        })
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_seq(FixedLenReader {
            de: self,
            remaining: len,
        })
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let len = self.read_len()?;
        visitor.visit_map(FixedLenReader {
            de: self,
            remaining: len,
        })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_seq(FixedLenReader {
            de: self,
            remaining: fields.len(),
        })
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        let variant = u32::from_be_bytes(self.read_array()?);
        visitor.visit_enum(EnumReader { de: self, variant })
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::DeserializeAnyNotSupported)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::DeserializeAnyNotSupported)
    }
}

struct FixedLenReader<'a, 'de> {
    de: &'a mut SliceDeserializer<'de>,
    remaining: usize,
}

impl<'de> SeqAccess<'de> for FixedLenReader<'_, 'de> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining.min(self.de.input.len()))
    }
}

impl<'de> MapAccess<'de> for FixedLenReader<'_, 'de> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        seed.deserialize(&mut *self.de)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining.min(self.de.input.len()))
    }
}

struct EnumReader<'a, 'de> {
    de: &'a mut SliceDeserializer<'de>,
    variant: u32,
}

impl<'a, 'de> EnumAccess<'de> for EnumReader<'a, 'de> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self::Variant)> {
        let val = seed.deserialize(VariantIndexDeserializer(self.variant))?;
        Ok((val, self))
    }
}

impl<'de> VariantAccess<'de> for EnumReader<'_, 'de> {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        seed.deserialize(self.de)
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        serde::Deserializer::deserialize_tuple(self.de, len, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(self, fields: &'static [&'static str], visitor: V) -> Result<V::Value> {
        serde::Deserializer::deserialize_struct(self.de, "", fields, visitor)
    }
}

struct VariantIndexDeserializer(u32);

impl<'de> serde::Deserializer<'de> for VariantIndexDeserializer {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u32(self.0)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Sample {
        magic: [u8; 4],
        version: u32,
        // Named for what it exercises - a 64-bit field - rather than after any real field,
        // so a search for a `u64` generation turns up nothing outside this encoding test.
        wide: u64,
    }

    fn sample() -> Sample {
        Sample {
            magic: *b"APPS",
            version: 1,
            wide: 258,
        }
    }

    #[test]
    fn test_integers_are_big_endian() {
        let bytes = serialize(&sample()).unwrap();
        // `version` follows the 4 magic bytes; big-endian puts its most significant byte
        // first, so a small value reads as leading zeroes rather than trailing ones.
        assert_eq!(&bytes[4..8], &1u32.to_be_bytes());
        assert_eq!(&bytes[8..16], &258u64.to_be_bytes());
    }

    #[test]
    fn test_widths_match_fixed_size_encoding() {
        // Varint encoding would make this shorter, and variable with the values it holds.
        // Anything that seeks past a serialized struct by a constant depends on this.
        let small = serialize(&sample()).unwrap();
        let large = serialize(&Sample {
            magic: *b"APPS",
            version: u32::MAX,
            wide: u64::MAX,
        })
        .unwrap();

        assert_eq!(small.len(), 4 + 4 + 8);
        assert_eq!(small.len(), large.len(), "encoded size must not depend on the values");
    }

    #[test]
    fn test_round_trip() {
        let value = sample();
        assert_eq!(deserialize::<Sample>(&serialize(&value).unwrap()).unwrap(), value);
    }

    #[test]
    fn test_little_endian_bytes_do_not_silently_decode() {
        // A file written by a little-endian encoding must not read back as the same
        // value. It cannot be detected here - both are valid byte strings - so the
        // check is that the *values* differ, which is what the format version gate exists to
        // catch before it matters.
        let mut le = Vec::new();
        le.extend_from_slice(b"APPS");
        le.extend_from_slice(&1u32.to_le_bytes());
        le.extend_from_slice(&258u64.to_le_bytes());
        let decoded: Sample = deserialize(&le).unwrap();
        assert_ne!(decoded, sample(), "byte order change must alter decoded values");
    }

    #[test]
    fn test_all_serde_primitives_and_containers() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        enum Variant {
            Unit,
            Newtype(i128),
            Tuple(char, f32, f64),
            Struct { flag: bool, text: String },
        }

        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Full {
            b: bool,
            i8v: i8,
            i16v: i16,
            i32v: i32,
            i64v: i64,
            i128v: i128,
            u8v: u8,
            u16v: u16,
            u32v: u32,
            u64v: u64,
            u128v: u128,
            f32v: f32,
            f64v: f64,
            ch_ascii: char,
            ch_multi: char,
            opt_none: Option<u32>,
            opt_some: Option<String>,
            vec_bytes: Vec<u8>,
            btree: BTreeMap<String, Vec<u8>>,
            hash: HashMap<String, u64>,
            variants: Vec<Variant>,
        }

        let mut btree = BTreeMap::new();
        btree.insert("k1".to_string(), vec![1, 2, 3]);
        let mut hash = HashMap::new();
        hash.insert("h1".to_string(), 99);

        let full = Full {
            b: true,
            i8v: -7,
            i16v: -300,
            i32v: -100_000,
            i64v: i64::MIN + 1,
            i128v: i128::MIN + 7,
            u8v: 250,
            u16v: 65_000,
            u32v: 3_000_000_000,
            u64v: u64::MAX - 5,
            u128v: u128::MAX - 9,
            f32v: 1.5,
            f64v: -2.25,
            ch_ascii: 'A',
            ch_multi: '🦀',
            opt_none: None,
            opt_some: Some("hello".to_string()),
            vec_bytes: vec![0, 1, 2, 255],
            btree,
            hash,
            variants: vec![
                Variant::Unit,
                Variant::Newtype(-42),
                Variant::Tuple('é', 3.25, 4.5),
                Variant::Struct {
                    flag: false,
                    text: "world".to_string(),
                },
            ],
        };

        let encoded = serialize(&full).unwrap();
        let decoded: Full = deserialize(&encoded).unwrap();
        assert_eq!(decoded, full);
    }

    #[test]
    fn test_rejects_malformed_and_trailing_bytes() {
        let bytes = serialize(&sample()).unwrap();
        assert!(deserialize::<Sample>(&bytes[..bytes.len() - 1]).is_err());

        let mut with_trailing = bytes;
        with_trailing.push(0);
        assert!(matches!(
            deserialize::<Sample>(&with_trailing),
            Err(Error::TrailingBytes)
        ));

        assert!(matches!(deserialize::<bool>(&[2]), Err(Error::InvalidBool(2))));
        assert!(matches!(
            deserialize::<Option<u8>>(&[2]),
            Err(Error::InvalidOptionTag(2))
        ));

        // Corrupt huge length prefix must fail with UnexpectedEof rather than OOM.
        let mut huge_len = Vec::new();
        huge_len.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(deserialize::<String>(&huge_len), Err(Error::UnexpectedEof)));
        assert!(matches!(deserialize::<Vec<u8>>(&huge_len), Err(Error::UnexpectedEof)));
    }
}
