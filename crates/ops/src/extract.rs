//! The only place untrusted archives touch disk. Paths that escape `dest` abort the whole
//! extraction (that itself is a red flag); links and device files are skipped.

use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};

pub const MAX_TOTAL: u64 = 200 << 20;
pub const MAX_FILES: usize = 20_000;

#[derive(Default, Debug)]
pub struct Stats {
    pub files: usize,
    pub bytes: u64,
    pub skipped_links: usize,
}

pub fn extract(archive: &[u8], dest: &Path) -> Result<Stats> {
    match archive {
        [0x1f, 0x8b, ..] => untar(flate2::read::GzDecoder::new(archive), dest),
        [b'P', b'K', ..] => unzip(archive, dest),
        _ => bail!("unknown archive format"),
    }
}

/// Relative path with only normal components, else an error.
fn safe_rel(p: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => bail!("archive entry escapes the extraction dir: {}", p.display()),
        }
    }
    Ok(out)
}

fn write_capped(dest: &Path, rel: &Path, mut r: impl Read, st: &mut Stats) -> Result<()> {
    st.files += 1;
    if st.files > MAX_FILES {
        bail!("more than {MAX_FILES} files");
    }
    let path = dest.join(rel);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut f = fs::File::create(&path)?;
    let budget = MAX_TOTAL - st.bytes;
    // read one byte past the budget so we can tell "exactly full" from "too big"
    let n = std::io::copy(&mut (&mut r).take(budget + 1), &mut f)?;
    if n > budget {
        bail!("archive expands past {} MB", MAX_TOTAL >> 20);
    }
    st.bytes += n;
    f.flush()?;
    Ok(())
}

fn untar(r: impl Read, dest: &Path) -> Result<Stats> {
    let mut st = Stats::default();
    let mut ar = tar::Archive::new(r);
    for e in ar.entries()? {
        let e = e?;
        let rel = safe_rel(&e.path()?)?;
        match e.header().entry_type() {
            tar::EntryType::Regular | tar::EntryType::Continuous => write_capped(dest, &rel, e, &mut st)?,
            tar::EntryType::Directory => fs::create_dir_all(dest.join(&rel))?,
            tar::EntryType::Symlink | tar::EntryType::Link => st.skipped_links += 1,
            _ => {} // device files, fifos, pax headers
        }
    }
    Ok(st)
}

fn unzip(data: &[u8], dest: &Path) -> Result<Stats> {
    let mut st = Stats::default();
    let mut ar = zip::ZipArchive::new(Cursor::new(data)).context("bad zip")?;
    for i in 0..ar.len() {
        let f = ar.by_index(i)?;
        let Some(name) = f.enclosed_name() else {
            bail!("archive entry escapes the extraction dir: {}", f.name());
        };
        let rel = safe_rel(&name)?;
        if f.is_symlink() {
            st.skipped_links += 1;
        } else if f.is_dir() {
            fs::create_dir_all(dest.join(&rel))?;
        } else {
            write_capped(dest, &rel, f, &mut st)?;
        }
    }
    Ok(st)
}
