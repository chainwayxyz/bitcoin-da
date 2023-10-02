use core::result::Result::Ok;
use core::str::FromStr;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};

use anyhow::Context;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::blockdata::opcodes::OP_FALSE;
use bitcoin::blockdata::script;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedKeyPair};
use bitcoin::psbt::Prevouts;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{self, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{
    Address, Amount, Network, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Witness,
};
use brotli::{CompressorWriter, DecompressorWriter};
use ord::{FeeRate, SatPoint, TransactionBuilder};

use crate::helpers::{BODY_TAG, PUBLICKEY_TAG, RANDOM_TAG, ROLLUP_NAME_TAG, SIGNATURE_TAG};
use crate::spec::utxo::UTXO;

pub fn get_satpoint_to_inscribe(utxo: &UTXO) -> SatPoint {
    let satpoint_str = utxo.tx_id.to_string() + ":" + &utxo.vout.to_string() + ":0"; // first offset
    SatPoint::from_str(&satpoint_str).unwrap()
}

pub fn compress_blob(blob: &[u8]) -> Vec<u8> {
    let mut writer = CompressorWriter::new(Vec::new(), 4096, 11, 22);
    writer.write_all(blob).unwrap();
    writer.into_inner()
}

pub fn decompress_blob(blob: &[u8]) -> Vec<u8> {
    let mut writer = DecompressorWriter::new(Vec::new(), 4096);
    writer.write_all(blob).unwrap();
    writer.into_inner().expect("decompression failed")
}

// Signs a message with a private key
pub fn sign_blob_with_private_key(
    blob: &[u8],
    private_key: &str,
) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let message = sha256d::Hash::hash(blob).to_byte_array();
    let secp = Secp256k1::new();
    let key = secp256k1::SecretKey::from_str(private_key).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &key);
    let msg = secp256k1::Message::from_slice(&message).unwrap();
    let sig = secp.sign_ecdsa(&msg, &key);
    Ok((
        sig.serialize_compact().to_vec(),
        public_key.serialize().to_vec(),
    ))
}

// Builds the inscription reveal transaction
fn build_reveal_transaction(
    control_block: &ControlBlock,
    fee_rate: f64,
    input: OutPoint,
    output: TxOut,
    script: &Script,
) -> (Transaction, Amount) {
    let reveal_tx = Transaction {
        input: vec![TxIn {
            previous_output: input,
            script_sig: script::Builder::new().into_script(),
            witness: Witness::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        }],
        output: vec![output],
        lock_time: LockTime::ZERO,
        version: 1,
    };

    let fee = {
        let mut reveal_tx = reveal_tx.clone();

        reveal_tx.input[0].witness.push(
            Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
                .unwrap()
                .as_ref(),
        );
        reveal_tx.input[0].witness.push(script);
        reveal_tx.input[0].witness.push(&control_block.serialize());

        Amount::from_sat((fee_rate * reveal_tx.vsize() as f64).round() as u64)
    };

    (reveal_tx, fee)
}

// Creates the inscription transactions (commit and reveal)
pub fn create_inscription_transactions(
    rollup_name: &str,
    body: Vec<u8>,
    signature: Vec<u8>,
    sequencer_public_key: Vec<u8>,
    satpoint: SatPoint,
    utxos: Vec<UTXO>,
    change: [Address; 2],
    destination: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
) -> Result<(Transaction, Transaction), anyhow::Error> {
    // Create commit key
    let secp256k1 = Secp256k1::new();
    let key_pair = UntweakedKeyPair::new(&secp256k1, &mut rand::thread_rng());
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let mut amounts: BTreeMap<OutPoint, Amount> = BTreeMap::new();

    for utxo in utxos {
        amounts.insert(
            OutPoint {
                txid: utxo.tx_id,
                vout: utxo.vout,
            },
            Amount::from_sat(utxo.amount),
        );
    }

    // start creating inscription content
    let reveal_script_builder = script::Builder::new()
        .push_slice(public_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(PushBytesBuf::try_from(ROLLUP_NAME_TAG.to_vec()).unwrap())
        .push_slice(PushBytesBuf::try_from(rollup_name.as_bytes().to_vec()).unwrap())
        .push_slice(PushBytesBuf::try_from(SIGNATURE_TAG.to_vec()).unwrap())
        .push_slice(PushBytesBuf::try_from(signature).unwrap())
        .push_slice(PushBytesBuf::try_from(PUBLICKEY_TAG.to_vec()).unwrap())
        .push_slice(PushBytesBuf::try_from(sequencer_public_key).unwrap())
        .push_slice(PushBytesBuf::try_from(RANDOM_TAG.to_vec()).unwrap());
    // This envelope is not finished yet. The random number will be added later and followed by the body

    // Start loop to find a random number that makes the first two bytes of the reveal tx hash 0
    let mut random: i64 = 0;
    loop {
        // ownerships are moved to the loop
        let mut reveal_script_builder = reveal_script_builder.clone();
        let change = change.clone();
        let amounts = amounts.clone();

        // push first random number and body tag
        reveal_script_builder = reveal_script_builder
            .push_int(random)
            .push_slice(PushBytesBuf::try_from(BODY_TAG.to_vec()).unwrap());

        // push body in chunks of 520 bytes
        for chunk in body.chunks(520) {
            reveal_script_builder =
                reveal_script_builder.push_slice(PushBytesBuf::try_from(chunk.to_vec()).unwrap());
        }
        // push end if
        reveal_script_builder = reveal_script_builder.push_opcode(OP_ENDIF);

        // finalize reveal script
        let reveal_script = reveal_script_builder.into_script();

        // create spend info for tapscript
        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .unwrap()
            .finalize(&secp256k1, public_key)
            .unwrap();

        // create control block for tapscript
        let control_block = taproot_spend_info
            .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
            .unwrap();

        // create commit tx address
        let commit_tx_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

        // create reveal tx to arrange fee
        let (_, reveal_fee) = build_reveal_transaction(
            &control_block,
            reveal_fee_rate,
            OutPoint::null(),
            TxOut {
                script_pubkey: destination.payload.script_pubkey(),
                value: 0,
            },
            &reveal_script,
        );

        // build commit tx
        let unsigned_commit_tx = TransactionBuilder::build_transaction_with_value(
            satpoint,
            BTreeMap::new(),
            amounts,
            commit_tx_address.clone(),
            change,
            FeeRate::try_from(commit_fee_rate).unwrap(),
            reveal_fee + Amount::from_sat(546),
        )
        .unwrap();

        let output_to_reveal = unsigned_commit_tx.output[0].clone();

        // build reveal tx
        let (mut reveal_tx, fee) = build_reveal_transaction(
            &control_block,
            reveal_fee_rate,
            OutPoint {
                txid: unsigned_commit_tx.txid(),
                vout: 0,
            },
            TxOut {
                script_pubkey: destination.clone().script_pubkey(),
                value: output_to_reveal.value,
            },
            &reveal_script,
        );

        reveal_tx.output[0].value = reveal_tx.output[0]
            .value
            .checked_sub(fee.to_sat())
            .context("commit transaction output value insufficient to pay transaction fee")
            .unwrap();

        if reveal_tx.output[0].value < reveal_tx.output[0].script_pubkey.dust_value().to_sat() {
            return Err(anyhow::anyhow!(
                "commit transaction output would be dust".to_string()
            ));
        }

        let reveal_hash = reveal_tx.txid().as_raw_hash().to_byte_array();

        // check if first two bytes are 0
        if reveal_hash.starts_with(&[0, 0]) {
            // start signing reveal tx
            let mut sighash_cache = SighashCache::new(&mut reveal_tx);

            // create data to sign
            let signature_hash = sighash_cache
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&[output_to_reveal]),
                    TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
                    bitcoin::sighash::TapSighashType::Default,
                )
                .unwrap();

            // sign reveal tx data
            let signature = secp256k1.sign_schnorr(
                &secp256k1::Message::from_slice(signature_hash.as_byte_array())
                    .expect("should be cryptographically secure hash"),
                &key_pair,
            );

            // add signature to witness and finalize reveal tx
            let witness = sighash_cache.witness_mut(0).unwrap();
            witness.push(signature.as_ref());
            witness.push(reveal_script);
            witness.push(&control_block.serialize());

            // check if inscription locked to the correct address
            let recovery_key_pair =
                key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());
            let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
            assert_eq!(
                Address::p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
                    network,
                ),
                commit_tx_address
            );

            return Ok((unsigned_commit_tx, reveal_tx));
        }

        random += 1;
    }
}

pub fn write_reveal_tx(tx: &[u8], tx_id: String) {
    let reveal_tx_file = File::create("reveal_".to_string() + &tx_id + ".tx").unwrap();
    let mut reveal_tx_writer = BufWriter::new(reveal_tx_file);
    reveal_tx_writer.write_all(tx).unwrap();
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::{OutPoint, Txid, Address, hashes::Hash, Transaction};
    use ord::SatPoint;

    use crate::{helpers::{builders::{compress_blob, decompress_blob}, parsers::parse_transaction}, spec::utxo::UTXO};


    #[test]
    fn compression_decompression() {
        let blob = std::fs::read("test_data/blob.txt").unwrap();

        // compress and measure time
        let time = std::time::Instant::now();
        let compressed_blob = compress_blob(&blob);
        println!("compression time: {:?}", time.elapsed());

        // decompress and measure time
        let time = std::time::Instant::now();
        let decompressed_blob = decompress_blob(&compressed_blob);
        println!("decompression time: {:?}", time.elapsed());

        assert_eq!(blob, decompressed_blob);

        // size
        println!("blob size: {}", blob.len());
        println!("compressed blob size: {}", compressed_blob.len());
        println!(
            "compression ratio: {}",
            (blob.len() as f64) / (compressed_blob.len() as f64)
        );
    }

    #[test]
    fn write_reveal_tx() {
        let tx = vec![100, 100, 100];
        let tx_id = "test_tx".to_string();
        
        super::write_reveal_tx(tx.as_slice(), tx_id);

        let file = std::fs::read("reveal_test_tx.tx").unwrap();

        assert_eq!(tx, file);

        std::fs::remove_file("reveal_test_tx.tx").unwrap();
    }

    #[test]
    fn create_inscription_transactions() {
        let rollup_name = "test_rollup";
        let body = vec![100; 1000];
        let signature = vec![100; 64];
        let sequencer_public_key = vec![100; 33];
        let address = Address::from_str("bc1qf6cfk4nd875y9tyey7eyetwnlsx6t3yvdtd0wl").unwrap().require_network(bitcoin::Network::Bitcoin).unwrap();
        let utxos = vec![
            UTXO { tx_id: Txid::from_str("4cfbec13cf1510545f285cceceb6229bd7b6a918a8f6eba1dbee64d26226a3b7").unwrap(), vout: 0, address: "bc1qf6cfk4nd875y9tyey7eyetwnlsx6t3yvdtd0wl".to_string(), script_pubkey: address.script_pubkey().to_hex_string(), amount: 1_000_000, confirmations: 100, spendable: true, solvable: true },
            UTXO { tx_id: Txid::from_str("44990141674ff56ed6fee38879e497b2a726cddefd5e4d9b7bf1c4e561de4347").unwrap(), vout: 0, address: "bc1qf6cfk4nd875y9tyey7eyetwnlsx6t3yvdtd0wl".to_string(), script_pubkey: address.script_pubkey().to_hex_string(), amount: 100_000, confirmations: 100, spendable: true, solvable: true },
            UTXO { tx_id: Txid::from_str("4dbe3c10ee0d6bf16f9417c68b81e963b5bccef3924bbcb0885c9ea841912325").unwrap(), vout: 0, address: "bc1qf6cfk4nd875y9tyey7eyetwnlsx6t3yvdtd0wl".to_string(), script_pubkey: address.script_pubkey().to_hex_string(), amount: 10_000, confirmations: 100, spendable: true, solvable: true }
        ];
        let satpoint = SatPoint::from_str(format!("{}:{}:0", utxos[2].tx_id, utxos[2].vout).as_str()).unwrap();
        let change_addresses = [
            Address::from_str("bc1qclz6pwlazvafxezuj4mpngkvzuyjv9nsyndhxd").unwrap().assume_checked(),
            Address::from_str("bc1qw6jw0atgyk2gh0r344qedvdacddkxvh8j5q4y5").unwrap().assume_checked()
        ];


        let (commit, reveal) = super::create_inscription_transactions(
            rollup_name,
            body.clone(),
            signature.clone(),
            sequencer_public_key.clone(),
            satpoint,
            utxos.clone(),
            change_addresses,
            address.clone(),
            12.0,
            10.0,
            bitcoin::Network::Bitcoin
        ).unwrap();

        // check pow
        assert!(reveal.txid().as_byte_array().starts_with(&[0,0]));

        // check outputs
        assert_eq!(commit.output.len(), 2, "commit tx should have 2 outputs");

        assert_eq!(reveal.output.len(), 1, "reveal tx should have 1 output");

        assert_eq!(commit.input[0].previous_output.txid, utxos[2].tx_id, "utxo to inscribe should be chosen correctly");
        assert_eq!(commit.input[0].previous_output.vout, utxos[2].vout, "utxo to inscribe should be chosen correctly");


        assert_eq!(reveal.input[0].previous_output.txid, commit.txid(), "reveal should use commit as input");
        assert_eq!(reveal.input[0].previous_output.vout, 0, "reveal should use commit as input");

        assert_eq!(reveal.output[0].script_pubkey, address.script_pubkey(), "reveal should pay to the correct address");

        // check inscription
        let inscription = parse_transaction(&reveal, rollup_name).unwrap();

        assert_eq!(inscription.body, body, "body should be correct");
        assert_eq!(inscription.signature, signature, "signature should be correct");
        assert_eq!(inscription.public_key, sequencer_public_key, "sequencer public key should be correct");
    }
}