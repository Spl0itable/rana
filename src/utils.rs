use bip39::Mnemonic;
use colored::Colorize;
use nostr::prelude::*;
use qrcode::render::unicode;
use qrcode::QrCode;
use rand_core::OsRng;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use zip::write::FileOptions;
use zip::ZipWriter;
use lettre::message::{Attachment, Message, SinglePart};
use lettre::{SmtpClient, Transport};
use pbkdf2::pbkdf2;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use aes::Aes256;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;

/// Benchmark the cores capabilities for key generation
pub fn benchmark_cores(cores: usize, pow_difficulty: u8) {
    let mut hashes_per_second_per_core = 0;

    println!("Benchmarking a single core for 5 seconds...");
    let now = Instant::now();
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    loop {
        let (_secret_key, public_key) = secp.generate_keypair(&mut rng);
        let (xonly_public_key, _) = public_key.x_only_public_key();
        get_leading_zero_bits(&xonly_public_key.serialize());
        hashes_per_second_per_core += 1;
        if now.elapsed().as_secs() > 5 {
            break;
        }
    }
    hashes_per_second_per_core /= 10;
    println!("A single core can mine roughly {hashes_per_second_per_core} h/s!");

    let estimated_hashes = 2_u128.pow(pow_difficulty as u32);
    println!("Searching for prefix of {pow_difficulty} specific bits");
    let estimate = estimated_hashes as f32 / hashes_per_second_per_core as f32 / cores as f32;
    println!("This is estimated to take about {estimate} seconds");
}
use std::io::{self, Write}; // add this import
/// Print private and public keys to the output
pub fn print_keys(
    keys: &Keys,
    vanity_npub: String,
    leading_zeroes: u8,
    mnemonic: Option<Mnemonic>,
) -> Result<()> {
    if leading_zeroes != 0 {
        println!("Leading zero bits:         {leading_zeroes}");
    } else if !vanity_npub.is_empty() {
        println!("Vanity npub found:         {vanity_npub}")
    }

    println!("{}", "Found matching Nostr public key:".green());
    println!("Hex public key: {:>66}", keys.public_key().to_string());

    println!("Npub public key: {:>64}", keys.public_key().to_bech32()?);

    if let Some(mnemonic) = mnemonic {
        println!("Mnemonic:         {mnemonic}");
    }

    let nsec = keys.secret_key()?.to_bech32()?;

    let password = generate_password();
    let zip_file = create_zip_file(&nsec, &password)?;

    println!("Password for zip file: {}", password);
    println!("Encrypted private key written to {}", zip_file.display());

    // prompt the user for the email address
    print!("Enter your email address: ");
    io::stdout().flush().unwrap();
    let mut email = String::new();
    io::stdin().read_line(&mut email)?;

    let smtp_address = "null";
    let smtp_port = 587; // use STARTTLS
    let smtp_username = "null";
    let smtp_password = "null";

    let email = Message::builder()
        .to(email.trim().parse().unwrap()) // use the email entered by the user
        .from(smtp_username.parse().unwrap())
        .subject("Encrypted Nostr private key")
        .unwrap();

    let smtp_client = SmtpClient::new_simple(smtp_address)?
        .credentials(smtp_username, smtp_password)
        .transport();

    smtp_client.send(email.into())?;

    Ok(())
}
    
    #[inline]
    pub fn get_leading_zero_bits(bytes: &[u8]) -> u8 {
        let mut res = 0_u8;
        for b in bytes {
            if *b == 0 {
                res += 8;
            } else {
                res += b.leading_zeros() as u8;
                return res;
            }
        }
        res
    }
    
    fn generate_password() -> String {
        let mut password = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut password);
        base64::encode_config(password, base64::URL_SAFE_NO_PAD)
    }
    
    fn create_zip_file(nsec: &str, password: &str) -> Result<PathBuf> {
        let file_path = PathBuf::from(format!("encrypted_private_key_{}.zip", password));
        let file = File::create(&file_path)?;
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o600);
        zip.start_file("nsec.txt", options)?;
        let mut encryptor = Aes256::new(GenericArray::from_slice(password.as_bytes()));
        let mut iv = [0u8; 16];
        let mut rng = OsRng;
        rng.fill_bytes(&mut iv);
        zip.write_all(&iv)?;
        let mut tag = [0u8; 32];
        let mut mac = Hmac::<Sha256>::new_varkey(password.as_bytes()).unwrap();
        mac.input(&iv);
        mac.input(nsec.as_bytes());
        mac.result(&mut tag).unwrap();
        zip.write_all(&tag)?;
        let mut cipher_text = [0u8; 48];
        cipher_text[..16].copy_from_slice(&iv);
        encryptor.encrypt_block(GenericArray::from_mut_slice(&mut cipher_text[16..]), &mut GenericArray::from_slice(nsec.as_bytes())[..16]);
        mac.input(&cipher_text[16..]);
        mac.result(&mut tag).unwrap();
        zip.write_all(&cipher_text)?;
        zip.write_all(&tag)?;
    
        Ok(file_path)
    }
    
