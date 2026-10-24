//! Program instruction decoders.
//!
//! Each decoder converts raw program calldata into a human-readable
//! [`DecodedInstruction`]. The [`DecoderRegistry`] dispatches to the
//! right decoder based on the program id.

use lee::AccountId;

pub mod ata;
pub mod native;
pub mod testimonial;
pub mod token;

/// A decoded, human-readable instruction.
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    pub program: String,
    pub operation: String,
    pub fields: Vec<(String, String)>,
    pub raw: Vec<u8>,
}

/// Trait for program-specific decoders.
pub trait ProgramDecoder: Send + Sync {
    fn program_ids(&self) -> Vec<AccountId>;

    /// Attempt to decode the raw calldata.
    /// Returns `None` if the data doesn't match this decoder's format.
    fn decode(&self, program_id: &AccountId, data: &[u8]) -> Option<DecodedInstruction>;
}

/// Registry of available decoders.
pub struct DecoderRegistry {
    decoders: Vec<Box<dyn ProgramDecoder>>,
}

impl DecoderRegistry {
    /// Create a registry with all built-in decoders.
    pub fn with_builtins() -> Self {
        Self {
            decoders: vec![
                Box::new(native::NativeDecoder),
                Box::new(token::TokenDecoder),
                Box::new(ata::AtaDecoder),
                Box::new(testimonial::TestimonialDecoder::new()),
            ],
        }
    }

    /// Register an additional decoder.
    pub fn register(&mut self, decoder: Box<dyn ProgramDecoder>) {
        self.decoders.push(decoder);
    }

    /// Decode calldata for a given program, returning the first matching
    /// decoder's result or a raw fallback.
    pub fn decode(&self, program_id: &AccountId, data: &[u8]) -> DecodedInstruction {
        for decoder in &self.decoders {
            let ids = decoder.program_ids();
            if (ids.is_empty() || ids.contains(program_id))
                && let Some(decoded) = decoder.decode(program_id, data)
            {
                return decoded;
            }
        }

        // Fallback: show raw calldata.
        DecodedInstruction {
            program: hex::encode(program_id.to_bytes()),
            operation: "Unknown".into(),
            fields: vec![("data_size".into(), format!("{} bytes", data.len()))],
            raw: data.to_vec(),
        }
    }
}

impl Default for DecoderRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}
