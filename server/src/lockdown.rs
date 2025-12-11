static WPCOD_USER: &str = "_wpcod\x00";

pub fn step1() -> anyhow::Result<()> {
    openbsd::pledge!("stdio inet rpath unix unveil id", "")?;
    openbsd::unveil!("/etc", "r")?;
    openbsd::unveil!(crate::status::MON_SOCK, "rw")?;
    openbsd::unveil::disable();
    openbsd::pledge!("stdio inet rpath unix id", "")?;
    Ok(())
}

pub fn step2(_need_unix_socket: bool) -> anyhow::Result<()> {
    let usr = unsafe { libc::getpwnam(WPCOD_USER.as_ptr() as *const libc::c_char) };
    if usr.is_null() {
        return Err(anyhow::Error::msg("getpwnam() failed"));
    }
    let (uid, gid) = unsafe {
        let s = &*usr;
        (s.pw_uid, s.pw_gid)
    };

    if unsafe { libc::setresgid(gid, gid, gid) } == -1 {
        return Err(anyhow::Error::msg("setresgid() failed"));
    }

    if unsafe { libc::setresuid(uid, uid, uid) } == -1 {
        return Err(anyhow::Error::msg("setresuid() failed"));
    }

    match _need_unix_socket {
        true => openbsd::pledge!("stdio inet unix", "")?,
        false => openbsd::pledge!("stdio inet", "")?,
    }
    Ok(())
}
