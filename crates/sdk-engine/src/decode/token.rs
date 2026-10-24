use super::{DecodedInstruction, ProgramDecoder};
use borsh::BorshDeserialize;
use lee::AccountId;

pub struct TokenDecoder;

#[derive(Debug, Clone, BorshDeserialize)]
enum FungibleTokenMessage {
    Mint { recipient: [u8; 32], amount: u128 },
    Transfer { recipient: [u8; 32], amount: u128 },
    Burn(u128),
}

impl TokenDecoder {
    pub fn name() -> &'static str {
        "token"
    }
}

impl ProgramDecoder for TokenDecoder {
    fn program_ids(&self) -> Vec<AccountId> {
        // Dynamic matching across token program definitions
        vec![]
    }

    fn decode(&self, program_id: &AccountId, data: &[u8]) -> Option<DecodedInstruction> {
        if let Ok(msg) = FungibleTokenMessage::try_from_slice(data) {
            match msg {
                FungibleTokenMessage::Mint { recipient, amount } => Some(DecodedInstruction {
                    program: hex::encode(program_id.to_bytes()),
                    operation: "Mint".into(),
                    fields: vec![
                        ("Recipient".into(), hex::encode(recipient)),
                        ("Amount".into(), amount.to_string()),
                    ],
                    raw: data.to_vec(),
                }),
                FungibleTokenMessage::Transfer { recipient, amount } => Some(DecodedInstruction {
                    program: hex::encode(program_id.to_bytes()),
                    operation: "Transfer".into(),
                    fields: vec![
                        ("Recipient".into(), hex::encode(recipient)),
                        ("Amount".into(), amount.to_string()),
                    ],
                    raw: data.to_vec(),
                }),
                FungibleTokenMessage::Burn(amount) => Some(DecodedInstruction {
                    program: hex::encode(program_id.to_bytes()),
                    operation: "Burn".into(),
                    fields: vec![("Amount".into(), amount.to_string())],
                    raw: data.to_vec(),
                }),
            }
        } else if data.len() == 16 {
            let amount = u128::from_le_bytes(data.try_into().unwrap());
            Some(DecodedInstruction {
                program: hex::encode(program_id.to_bytes()),
                operation: "TokenTransferAmount".into(),
                fields: vec![("Amount".into(), amount.to_string())],
                raw: data.to_vec(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_token_amount() {
        let decoder = TokenDecoder;
        let dummy_program = AccountId::new([88u8; 32]);
        let amount: u128 = 250000;
        let bytes = amount.to_le_bytes();

        let decoded = decoder.decode(&dummy_program, &bytes);
        assert!(decoded.is_some());
        let d = decoded.unwrap();
        assert_eq!(d.operation, "TokenTransferAmount");
        assert_eq!(d.fields[0].1, "250000");
    }
}
