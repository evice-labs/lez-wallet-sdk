use super::{DecodedInstruction, ProgramDecoder};
use borsh::BorshDeserialize;
use lee::AccountId;
use lee_core::native_token::{Message, NATIVE_TOKEN_PROGRAM_ID};

pub struct NativeDecoder;

impl NativeDecoder {
    pub fn name() -> &'static str {
        "native"
    }
}

impl ProgramDecoder for NativeDecoder {
    fn program_ids(&self) -> Vec<AccountId> {
        vec![NATIVE_TOKEN_PROGRAM_ID]
    }

    fn decode(&self, program_id: &AccountId, data: &[u8]) -> Option<DecodedInstruction> {
        if *program_id != NATIVE_TOKEN_PROGRAM_ID {
            return None;
        }

        if let Ok(msg) = Message::try_from_slice(data) {
            match msg {
                Message::Transfer { to, amount } => Some(DecodedInstruction {
                    program: "native_token".into(),
                    operation: "Transfer".into(),
                    fields: vec![
                        ("Recipient".into(), hex::encode(to.to_bytes())),
                        ("Amount".into(), format!("{} LEZ", amount)),
                    ],
                    raw: data.to_vec(),
                }),
                Message::Credit(amount) => Some(DecodedInstruction {
                    program: "native_token".into(),
                    operation: "Credit".into(),
                    fields: vec![("Amount".into(), format!("{} LEZ", amount))],
                    raw: data.to_vec(),
                }),
                Message::ReadState => Some(DecodedInstruction {
                    program: "native_token".into(),
                    operation: "ReadState".into(),
                    fields: vec![],
                    raw: data.to_vec(),
                }),
            }
        } else if data.len() == 16 {
            // Raw balance encoding
            let amount = u128::from_le_bytes(data.try_into().unwrap());
            Some(DecodedInstruction {
                program: "native_token".into(),
                operation: "BalanceTransfer".into(),
                fields: vec![("Amount".into(), format!("{} LEZ", amount))],
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
    fn test_decode_native_transfer() {
        let decoder = NativeDecoder;
        let recipient = AccountId::new([42u8; 32]);
        let msg = Message::Transfer {
            to: recipient,
            amount: 5000,
        };
        let bytes = borsh::to_vec(&msg).unwrap();

        let decoded = decoder.decode(&NATIVE_TOKEN_PROGRAM_ID, &bytes);
        assert!(decoded.is_some());
        let d = decoded.unwrap();
        assert_eq!(d.operation, "Transfer");
        assert_eq!(d.fields[1].1, "5000 LEZ");
    }
}
