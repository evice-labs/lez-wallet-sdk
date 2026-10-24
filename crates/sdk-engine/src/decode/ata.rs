use super::{DecodedInstruction, ProgramDecoder};
use borsh::BorshDeserialize;
use lee::AccountId;

pub struct AtaDecoder;

#[derive(Debug, Clone, BorshDeserialize)]
enum HoldingMessage {
    Initialize {
        definition: [u8; 32],
        owner: [u8; 32],
    },
}

impl AtaDecoder {
    pub fn name() -> &'static str {
        "ata"
    }
}

impl ProgramDecoder for AtaDecoder {
    fn program_ids(&self) -> Vec<AccountId> {
        vec![]
    }

    fn decode(&self, program_id: &AccountId, data: &[u8]) -> Option<DecodedInstruction> {
        if let Ok(msg) = HoldingMessage::try_from_slice(data) {
            match msg {
                HoldingMessage::Initialize { definition, owner } => Some(DecodedInstruction {
                    program: hex::encode(program_id.to_bytes()),
                    operation: "InitializeHolding".into(),
                    fields: vec![
                        ("Definition".into(), hex::encode(definition)),
                        ("Owner".into(), hex::encode(owner)),
                    ],
                    raw: data.to_vec(),
                }),
            }
        } else {
            None
        }
    }
}
