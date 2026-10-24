//! The one module that is allowed `unsafe`.

#![allow(unsafe_code)]

pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, touches no memory and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    #[test]
    fn effective_uid_owns_new_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");

        std::fs::write(&path, b"x").unwrap();

        assert_eq!(std::fs::metadata(&path).unwrap().uid(), effective_uid());
    }
}
