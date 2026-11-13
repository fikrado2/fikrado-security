use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub fn shred_file<F>(file_path: &Path, passes: u32, mut progress_cb: F) -> Result<String, String>
where
    F: FnMut(u32, u32, &str),
{
    if !file_path.exists() {
        return Err("Target file does not exist.".to_string());
    }

    let file_len = file_path
        .metadata()
        .map_err(|e| e.to_string())?
        .len() as usize;

    let chunk_size = 64 * 1024;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(file_path)
        .map_err(|e| format!("Cannot open file for shredding: {}", e))?;

    let num_passes = passes.clamp(1, 7);

    for current_pass in 1..=num_passes {
        progress_cb(
            current_pass,
            num_passes,
            &format!("Overwriting pass {} of {}...", current_pass, num_passes),
        );

        let pattern_byte: Option<u8> = match current_pass % 3 {
            1 => Some(0x00),
            2 => Some(0xFF),
            _ => None, // pseudo-random
        };

        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;

        let mut written = 0;
        let mut seed = (current_pass as u64) * 6364136223846793005 + 1442695040888963407;

        while written < file_len {
            let to_write = (file_len - written).min(chunk_size);
            let buf = if let Some(b) = pattern_byte {
                vec![b; to_write]
            } else {
                let mut b = vec![0u8; to_write];
                for item in b.iter_mut() {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *item = (seed >> 32) as u8;
                }
                b
            };

            file.write_all(&buf).map_err(|e| e.to_string())?;
            written += to_write;
        }

        file.flush().map_err(|e| e.to_string())?;
    }

    // Truncate to 0
    file.set_len(0).map_err(|e| e.to_string())?;
    drop(file);

    // Delete file
    std::fs::remove_file(file_path).map_err(|e| format!("Failed to delete shredded file: {}", e))?;

    Ok(format!(
        "File '{}' permanently erased with {} overwrite passes.",
        file_path.display(),
        num_passes
    ))
}
