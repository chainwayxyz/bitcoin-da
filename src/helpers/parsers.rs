use core::iter::Peekable;

use bitcoin::blockdata::opcodes::all::{OP_ENDIF, OP_IF};
use bitcoin::blockdata::script::{Instruction, Instructions};
use bitcoin::hashes::sha256d;
use bitcoin::secp256k1::{self, ecdsa, Message, Secp256k1};
use bitcoin::{Script, Transaction};
use serde::{Deserialize, Serialize};

use super::{BODY_TAG, PUBLICKEY_TAG, RANDOM_TAG, ROLLUP_NAME_TAG, SIGNATURE_TAG};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedInscription {
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub fn parse_transaction(tx: &Transaction, rollup_name: &str) -> Result<ParsedInscription, ()> {
    let script = get_script(tx)?;
    let mut instructions = script.instructions().peekable();
    parse_relevant_inscriptions(&mut instructions, rollup_name)
}

// Returns the script from the first input of the transaction
fn get_script(tx: &Transaction) -> Result<&Script, ()> {
    tx.input[0].witness.tapscript().ok_or(())
}

// Parses the inscription from script if it is relevant to the rollup
fn parse_relevant_inscriptions(
    instructions: &mut Peekable<Instructions>,
    rollup_name: &str,
) -> Result<ParsedInscription, ()> {
    while let Some(instruction) = instructions.next() {
        let instruction = match instruction {
            Ok(i) => i,
            _ => continue,
        };

        match instruction {
            Instruction::PushBytes(bytes) if bytes.as_bytes() == BODY_TAG => {}
            _ => continue,
        }

        let op = match instructions.next() {
            Some(Ok(Instruction::Op(op))) => op,
            _ => continue,
        };

        if op != OP_IF {
            continue;
        }

        match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes() == ROLLUP_NAME_TAG => bytes,
            _ => continue,
        };

        let rollup_name_bytes = rollup_name.as_bytes();
        match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes() == rollup_name_bytes => {
                bytes
            }
            _ => continue,
        };

        match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes() == SIGNATURE_TAG => bytes,
            _ => continue,
        };

        let signature = match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
            _ => continue,
        };
        // Found signature

        match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes() == PUBLICKEY_TAG => bytes,
            _ => continue,
        };

        let public_key = match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
            _ => continue,
        };
        // Found public key

        match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes() == RANDOM_TAG => bytes,
            _ => continue,
        };

        match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
            _ => continue,
        };
        // Found random

        match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes() == BODY_TAG => bytes,
            _ => continue,
        };

        let mut body: Vec<u8> = Vec::new();
        loop {
            match instructions.next() {
                Some(Ok(Instruction::PushBytes(bytes))) => {
                    body.extend(bytes.as_bytes());
                }
                Some(Ok(Instruction::Op(op))) if op == OP_ENDIF => {
                    return Ok(ParsedInscription {
                        body,
                        signature: signature.to_vec(),
                        public_key: public_key.to_vec(),
                    });
                }
                _ => break,
            }
        }
    }

    // return error
    Err(())
}

// Recovers the sequencer public key from the transaction
pub fn recover_sender_and_hash_from_tx(tx: &Transaction, rollup_name: &str) -> Result<(Vec<u8>, [u8; 32]), ()> {
    let script = get_script(tx)?;
    let mut instructions = script.instructions().peekable();
    let parsed_inscription = parse_relevant_inscriptions(&mut instructions, rollup_name)?;
    let public_key = secp256k1::PublicKey::from_slice(&parsed_inscription.public_key).unwrap();
    let signature = ecdsa::Signature::from_compact(&parsed_inscription.signature).unwrap();

    let message = Message::from_hashed_data::<sha256d::Hash>(&parsed_inscription.body);

    let secp = Secp256k1::new();

    let verified = secp.verify_ecdsa(&message, &signature, &public_key).is_ok();

    if verified {
        Ok((public_key.serialize().to_vec(), *message.as_ref()))
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{ key::XOnlyPublicKey, script::{self, PushBytesBuf}, opcodes::{all::{OP_CHECKSIG, OP_IF, OP_ENDIF}, OP_FALSE}};

    use super::{BODY_TAG, ROLLUP_NAME_TAG, RANDOM_TAG, PUBLICKEY_TAG, SIGNATURE_TAG, parse_relevant_inscriptions};

    #[test]
    fn wrong_rollup_tag () {
        let reveal_script_builder = script::Builder::new()
            .push_slice(XOnlyPublicKey::from_slice(&[1; 32]).unwrap().serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from("not-sov-btc".as_bytes().to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from([0u8; 64]).unwrap())
            .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
            .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
            .push_int(0)
            .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
            .push_opcode(OP_ENDIF);

        let reveal_script = reveal_script_builder.into_script();

        let result = parse_relevant_inscriptions(&mut reveal_script.instructions().peekable(), "sov-btc");

        assert!(result.is_err());
    }

    #[test]
    fn leave_out_tags () {
        // name
        let reveal_script_builder = script::Builder::new()
        .push_slice(XOnlyPublicKey::from_slice(&[1; 32]).unwrap().serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
        .push_slice(PushBytesBuf::try_from([0u8; 64]).unwrap())
        .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
        .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
        .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
        .push_int(0)
        .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
        .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
        .push_opcode(OP_ENDIF);

        let reveal_script = reveal_script_builder.into_script();

        let result = parse_relevant_inscriptions(&mut reveal_script.instructions().peekable(), "sov-btc");

        assert!(result.is_err(), "Failed to error on no name tag.");

        // signature
        let reveal_script_builder = script::Builder::new()
            .push_slice(XOnlyPublicKey::from_slice(&[1; 32]).unwrap().serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
            .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
            .push_int(0)
            .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
            .push_opcode(OP_ENDIF);

        let reveal_script = reveal_script_builder.into_script();

        let result = parse_relevant_inscriptions(&mut reveal_script.instructions().peekable(), "sov-btc");

        assert!(result.is_err(), "Failed to error on no signature tag.");

        // publickey
        let reveal_script_builder = script::Builder::new()
            .push_slice(XOnlyPublicKey::from_slice(&[1; 32]).unwrap().serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from([0u8; 64]).unwrap())
            .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
            .push_int(0)
            .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
            .push_opcode(OP_ENDIF);

        let reveal_script = reveal_script_builder.into_script();

        let result = parse_relevant_inscriptions(&mut reveal_script.instructions().peekable(), "sov-btc");

        assert!(result.is_err(), "Failed to error on no publickey tag.");

        // body
        let reveal_script_builder = script::Builder::new()
            .push_slice(XOnlyPublicKey::from_slice(&[1; 32]).unwrap().serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from([0u8; 64]).unwrap())
            .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
            .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap())
            .push_int(0)
            .push_opcode(OP_ENDIF);

        let reveal_script = reveal_script_builder.into_script();

        let result = parse_relevant_inscriptions(&mut reveal_script.instructions().peekable(), "sov-btc");

        assert!(result.is_err(), "Failed to error on no body tag.");

        // random
        let reveal_script_builder = script::Builder::new()
            .push_slice(XOnlyPublicKey::from_slice(&[1; 32]).unwrap().serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from("sov-btc".as_bytes().to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from([0u8; 64]).unwrap())
            .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![0u8; 64]).unwrap())
            .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![0u8; 128]).unwrap())
            .push_opcode(OP_ENDIF);

        let reveal_script = reveal_script_builder.into_script();

        let result = parse_relevant_inscriptions(&mut reveal_script.instructions().peekable(), "sov-btc");

        assert!(result.is_err(), "Failed to error on no random tag.");
    }

}