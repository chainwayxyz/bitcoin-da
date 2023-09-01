use core::result::Result::Ok;
use core::str::FromStr;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};

use anyhow::Context;
use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::blockdata::opcodes::OP_FALSE;
use bitcoin::blockdata::script;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::psbt::Prevouts;
use bitcoin::schnorr::{TapTweak, TweakedPublicKey, UntweakedKeyPair};
use bitcoin::secp256k1::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::util::sighash::SighashCache;
use bitcoin::util::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{
    Address, Amount, Network, OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut,
    Witness, XOnlyPublicKey,
};
use ord::{FeeRate, SatPoint, TransactionBuilder};

use crate::helpers::{BODY_TAG, PUBLICKEY_TAG, ROLLUP_NAME_TAG, SIGNATURE_TAG};
use crate::spec::utxo::UTXO;

pub fn get_satpoint_to_inscribe(utxo: &UTXO) -> SatPoint {
    let satpoint_str = utxo.tx_id.to_string() + ":" + &utxo.vout.to_string() + ":0"; // first offset
    SatPoint::from_str(&satpoint_str).unwrap()
}

// Signs a message with a private key
pub fn sign_blob_with_private_key(
    blob: &[u8],
    private_key: &str,
) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let message = sha256d::Hash::hash(blob).into_inner();
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
        lock_time: PackedLockTime::ZERO,
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

    // create inscription content
    let mut reveal_script_builder = script::Builder::new()
        .push_slice(&public_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(ROLLUP_NAME_TAG)
        .push_slice(rollup_name.as_bytes())
        .push_slice(SIGNATURE_TAG)
        .push_slice(&signature)
        .push_slice(PUBLICKEY_TAG)
        .push_slice(&sequencer_public_key)
        .push_slice(BODY_TAG);

    for chunk in body.chunks(520) {
        reveal_script_builder = reveal_script_builder.push_slice(chunk);
    }

    reveal_script_builder = reveal_script_builder.push_opcode(OP_ENDIF);

    let reveal_script = reveal_script_builder.into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .unwrap()
        .finalize(&secp256k1, public_key)
        .unwrap();

    let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .unwrap();

    let commit_tx_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

    let (_, reveal_fee) = build_reveal_transaction(
        &control_block,
        reveal_fee_rate,
        OutPoint::null(),
        TxOut {
            script_pubkey: destination.script_pubkey(),
            value: 0,
        },
        &reveal_script,
    );

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

    let unsigned_commit_tx: Transaction = TransactionBuilder::build_transaction_with_value(
        satpoint,
        BTreeMap::new(),
        amounts,
        commit_tx_address.clone(),
        change,
        FeeRate::try_from(commit_fee_rate).unwrap(),
        reveal_fee + Amount::from_sat(546),
    )
    .unwrap();

    let (vout, output) = unsigned_commit_tx
        .output
        .iter()
        .enumerate()
        .find(|(_vout, output)| {
            output.script_pubkey.to_bytes() == commit_tx_address.script_pubkey().to_bytes()
        })
        .unwrap();

    let (mut reveal_tx, fee) = build_reveal_transaction(
        &control_block,
        reveal_fee_rate,
        OutPoint {
            txid: unsigned_commit_tx.txid(),
            vout: vout.try_into().unwrap(),
        },
        TxOut {
            script_pubkey: destination.script_pubkey(),
            value: output.value,
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

    let mut sighash_cache = SighashCache::new(&mut reveal_tx);

    let signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[output]),
            TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
            bitcoin::SchnorrSighashType::Default,
        )
        .unwrap();

    let signature = secp256k1.sign_schnorr(
        &secp256k1::Message::from_slice(signature_hash.as_inner())
            .expect("should be cryptographically secure hash"),
        &key_pair,
    );

    let witness = sighash_cache.witness_mut(0).unwrap();
    witness.push(signature.as_ref());
    witness.push(reveal_script);
    witness.push(&control_block.serialize());

    let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());

    let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
    assert_eq!(
        Address::p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
            network,
        ),
        commit_tx_address
    );

    Ok((unsigned_commit_tx, reveal_tx))
}

pub fn write_reveal_tx(tx: &[u8], tx_id: String) {
    let reveal_tx_file = File::create("reveal_".to_string() + &tx_id + ".tx").unwrap();
    let mut reveal_tx_writer = BufWriter::new(reveal_tx_file);
    reveal_tx_writer.write_all(tx).unwrap();
}