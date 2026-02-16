use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use bhd_decrypter::{RsaPublicKey, decrypt_into, parse_pem_public_key};
use clap::Parser;
use rayon::prelude::*;

#[derive(Parser)]
#[command(name = "BHD decryptor")]
struct Args {
    /// Input directory containing encrypted .bhd files
    #[arg(short, long, default_value = ".")]
    input: String,

    /// Output directory for decrypted files
    #[arg(short, long, default_value = "output")]
    output: String,

    /// Keys directory containing .pem files
    #[arg(short, long, default_value = "keys")]
    keys: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    fs::create_dir_all(&args.output)?;

    let keys = load_keys(&args.keys)?;
    println!("Loaded {} keys", keys.len());

    keys.par_iter().for_each(|(name, public_key)| {
        let input_path = Path::new(&args.input).join(format!("{}.bhd", name));

        if input_path.exists() {
            if let Err(e) = process_file(&input_path, &args.output, public_key) {
                eprintln!("Error processing {:?}: {}", input_path, e);
            }
        } else {
            println!("Skipping {}.bhd (not found)", name);
        }
    });

    println!("Done!");
    Ok(())
}

fn load_keys(keys_dir: &str) -> Result<Vec<(String, RsaPublicKey)>, Box<dyn std::error::Error>> {
    let mut keys = Vec::new();

    for entry in fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "pem") {
            let name = path.file_stem().unwrap().to_str().unwrap().to_string();

            let key_pem = fs::read_to_string(&path)?;
            let public_key = parse_pem_public_key(&key_pem)?;

            println!("Loaded key: {}", name);
            keys.push((name, public_key));
        }
    }

    Ok(keys)
}

fn process_file(
    input_path: &Path,
    output_dir: &str,
    public_key: &RsaPublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Processing: {:?}", input_path);

    let encrypted_data = fs::read(input_path)?;

    let decrypted_data = decrypt_bhd(&encrypted_data, public_key);

    if decrypted_data.len() >= 4 && &decrypted_data[0..4] == b"BHD5" {
        println!("  -> Valid BHD5 header");
    } else {
        println!(
            "  -> Warning: No BHD5 magic found (got {:02X?})",
            &decrypted_data[..4.min(decrypted_data.len())]
        );
    }

    let output_path = Path::new(output_dir).join(input_path.file_name().unwrap());

    let output_file = File::create(&output_path)?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, output_file);
    writer.write_all(&decrypted_data)?;

    println!(
        "  -> Saved to {:?} ({} bytes)",
        output_path,
        decrypted_data.len()
    );
    Ok(())
}

fn decrypt_bhd(data: &[u8], public_key: &RsaPublicKey) -> Vec<u8> {
    let in_block_size = public_key.size;
    let out_block_size = public_key.size - 1;

    if data.len() < in_block_size {
        return data.to_vec();
    }

    let n = &public_key.n;
    let e = &public_key.e;

    let block_count = data.len().div_ceil(in_block_size);
    let mut result = vec![0u8; block_count * out_block_size];

    let in_chunk_iter = data.par_chunks_exact(in_block_size);
    let last_in_chunk = in_chunk_iter.remainder();

    in_chunk_iter
        .zip(result.par_chunks_exact_mut(out_block_size))
        .for_each(|(in_chunk, out_chunk)| {
            decrypt_into(in_chunk, n, e, out_chunk);
        });

    if !last_in_chunk.is_empty()
        && let Some(last_out_chunk) = result.chunks_mut(out_block_size).last()
    {
        let mut padded_block = Vec::with_capacity(in_block_size);
        padded_block.extend_from_slice(last_in_chunk);
        padded_block.resize(in_block_size, 0);

        decrypt_into(&padded_block, n, e, last_out_chunk);
    }

    result
}
