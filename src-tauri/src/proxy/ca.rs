//! CA 证书管理：生成自签名根 CA（rcgen 0.14）、安全持久化、导出、
//! Windows 信任安装/检测。私钥只存在本机受保护的 app_data_dir/ca。

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use hudsucker::rustls::crypto::aws_lc_rs;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

/// CA 证书 CN，Windows 证书管理器里按这个名字找。
pub const CA_COMMON_NAME: &str = "RustForge MITM CA";

/// 磁盘上的 CA 材料。私钥路径不进入结构体，也不通过命令或日志暴露。
pub struct CaMaterial {
    pub cert_pem: String,
    pub key_pem: Zeroizing<String>,
    pub cert_path: PathBuf,
}

fn ca_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (
        dir.join("ca").join("rustforge-ca.cer"),
        dir.join("ca").join("rustforge-ca.key"),
    )
}

fn path_exists_without_following_links(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err("CA 材料不得是符号链接；请清理 CA 目录后重试".into());
            }
            if !metadata.is_file() {
                return Err("CA 材料路径不是普通文件；请清理 CA 目录后重试".into());
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("检查 CA 材料失败: {error}")),
    }
}

#[cfg(unix)]
fn secure_ca_directory(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fs::create_dir_all(dir).map_err(|error| format!("创建 CA 目录失败: {error}"))?;
    let metadata =
        fs::symlink_metadata(dir).map_err(|error| format!("检查 CA 目录失败: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("CA 目录必须是当前用户拥有的普通目录".into());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("CA 目录不属于当前用户，无法安全启动代理；请修复所有者后重试".into());
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("CA 目录权限过宽且无法收紧: {error}"))?;
    let mode = fs::metadata(dir)
        .map_err(|error| format!("复查 CA 目录权限失败: {error}"))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err("CA 目录权限无法收紧为仅当前用户可访问，代理已停止".into());
    }
    Ok(())
}

#[cfg(unix)]
fn secure_private_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("检查 CA 私钥失败: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("CA 私钥必须是当前用户拥有的普通文件".into());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("CA 私钥不属于当前用户，无法安全启动代理；请修复所有者后重试".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("CA 私钥权限过宽且无法收紧: {error}"))?;
    let mode = fs::metadata(path)
        .map_err(|error| format!("复查 CA 私钥权限失败: {error}"))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err("CA 私钥权限无法收紧为仅当前用户可读写，代理已停止".into());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn apply_and_verify_current_user_acl(path: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    // 只给当前 Windows SID 完全控制权限，关闭继承并移除所有既有访问规则；
    // 随后重新读取 DACL，确认不存在其他主体或继承项。
    const ACL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
$target = $env:RUSTFORGE_ACL_TARGET
if ([string]::IsNullOrWhiteSpace($target)) { throw 'missing target' }
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$item = Get-Item -LiteralPath $target -Force
$acl = Get-Acl -LiteralPath $target
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) {
  throw 'unexpected ACL owner'
}
$acl.SetAccessRuleProtection($true, $false)
$rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
foreach ($rule in $rules) {
  [void]$acl.RemoveAccessRuleSpecific($rule)
}
$inheritance = [System.Security.AccessControl.InheritanceFlags]::None
if ($item.PSIsContainer) {
  $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                 [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
}
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
  $sid,
  [System.Security.AccessControl.FileSystemRights]::FullControl,
  $inheritance,
  [System.Security.AccessControl.PropagationFlags]::None,
  [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($rule)
$item.SetAccessControl($acl)
$verified = Get-Acl -LiteralPath $target
$verifiedRules = @($verified.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
if (-not $verified.AreAccessRulesProtected) { throw 'ACL inheritance remains enabled' }
if ($verifiedRules.Count -ne 1) { throw 'unexpected ACL rule count' }
if ($verifiedRules[0].IdentityReference.Value -ne $sid.Value) { throw 'unexpected ACL identity' }
if ($verifiedRules[0].AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
  throw 'unexpected ACL type'
}
"#;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let system_root =
        std::env::var_os("SystemRoot").unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows"));
    let module_path = PathBuf::from(system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("Modules");
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ACL_SCRIPT,
        ])
        .env("RUSTFORGE_ACL_TARGET", path.as_os_str())
        // 从 PowerShell 7 或开发 shell 启动时可能继承不兼容的 PSModulePath；
        // ACL 脚本只加载 Windows PowerShell 自带的 Security 模块。
        .env("PSModulePath", module_path)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|_| {
            "无法调用 Windows ACL 工具；代理已停止，请确认 Windows PowerShell 可用".to_string()
        })?;
    if !output.status.success() {
        return Err(
            "CA 私钥 ACL 无法收紧为仅当前用户可访问；代理已停止，请检查应用数据目录所有者".into(),
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn secure_ca_directory(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|error| format!("创建 CA 目录失败: {error}"))?;
    let metadata =
        fs::symlink_metadata(dir).map_err(|error| format!("检查 CA 目录失败: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("CA 目录必须是当前用户拥有的普通目录".into());
    }
    apply_and_verify_current_user_acl(dir)
}

#[cfg(target_os = "windows")]
fn secure_private_file(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("检查 CA 私钥失败: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("CA 私钥必须是当前用户拥有的普通文件".into());
    }
    apply_and_verify_current_user_acl(path)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn secure_ca_directory(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|error| format!("创建 CA 目录失败: {error}"))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn secure_private_file(_path: &Path) -> Result<(), String> {
    Err("当前平台不支持 CA 私钥权限校验，代理已停止".into())
}

struct TempPathGuard {
    path: PathBuf,
    committed: bool,
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_temp_file(dest: &Path, private: bool) -> Result<(File, TempPathGuard), String> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = dest.parent().ok_or("CA 临时文件目录解析失败")?;
    let name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("CA 文件名无效")?;

    for _ in 0..100 {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), counter));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp) {
            Ok(file) => {
                let guard = TempPathGuard {
                    path: temp,
                    committed: false,
                };
                if private {
                    secure_private_file(&guard.path)?;
                }
                return Ok((file, guard));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("创建 CA 临时文件失败: {error}")),
        }
    }
    Err("无法创建唯一的 CA 临时文件".into())
}

fn atomic_write(dest: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
    let (mut file, mut guard) = create_temp_file(dest, private)?;
    file.write_all(bytes)
        .map_err(|error| format!("写入 CA 临时文件失败: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("同步 CA 临时文件失败: {error}"))?;
    drop(file);
    fs::rename(&guard.path, dest).map_err(|error| format!("提交 CA 文件失败: {error}"))?;
    guard.committed = true;
    if private {
        secure_private_file(dest)?;
    }
    #[cfg(unix)]
    {
        let parent = dest.parent().ok_or("CA 目录解析失败")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("同步 CA 目录失败: {error}"))?;
    }
    Ok(())
}

/// 加载已有 CA；两份材料都不存在时生成新的自签名根 CA并安全落盘。
pub fn ensure_ca(app_data_dir: &Path) -> Result<CaMaterial, String> {
    let (cert_path, key_path) = ca_paths(app_data_dir);
    let dir = cert_path.parent().ok_or("CA 目录解析失败")?;
    secure_ca_directory(dir)?;

    let cert_exists = path_exists_without_following_links(&cert_path)?;
    let key_exists = path_exists_without_following_links(&key_path)?;
    match (cert_exists, key_exists) {
        (true, true) => {
            secure_private_file(&key_path)?;
            let cert_pem = fs::read_to_string(&cert_path)
                .map_err(|error| format!("读取 CA 证书失败: {error}"))?;
            let key_pem = Zeroizing::new(
                fs::read_to_string(&key_path)
                    .map_err(|error| format!("读取 CA 私钥失败: {error}"))?,
            );
            Ok(CaMaterial {
                cert_pem,
                key_pem,
                cert_path,
            })
        }
        (false, false) => generate_ca(cert_path, key_path),
        _ => {
            Err("CA 证书与私钥不完整，为避免覆盖或错配已停止代理；请清理 CA 目录后重新生成".into())
        }
    }
}

fn generate_ca(cert_path: PathBuf, key_path: PathBuf) -> Result<CaMaterial, String> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, CA_COMMON_NAME);
    distinguished_name.push(
        DnType::OrganizationName,
        "RustForge (Authorized Testing Only)",
    );
    params.distinguished_name = distinguished_name;
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2035, 12, 31);

    let key_pair = KeyPair::generate().map_err(|error| format!("生成 CA 密钥失败: {error}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|error| format!("自签 CA 证书失败: {error}"))?;
    let cert_pem = cert.pem();
    let key_pem = Zeroizing::new(key_pair.serialize_pem());

    // 私钥先写到受保护的临时文件并同步，再原子提交；最终文件不会出现部分 PEM。
    atomic_write(&key_path, key_pem.as_bytes(), true)?;
    atomic_write(&cert_path, cert_pem.as_bytes(), false)?;

    Ok(CaMaterial {
        cert_pem,
        key_pem,
        cert_path,
    })
}

/// 从 PEM 材料构建 hudsucker 的证书颁发机构（内含站点证书缓存）。
pub fn build_authority(material: &CaMaterial) -> Result<RcgenAuthority, String> {
    let key_pair = KeyPair::from_pem(&material.key_pem)
        .map_err(|error| format!("CA 私钥解析失败: {error}"))?;
    let issuer = Issuer::from_ca_cert_pem(&material.cert_pem, key_pair)
        .map_err(|error| format!("CA 证书解析失败: {error}"))?;
    Ok(RcgenAuthority::new(
        issuer,
        1_000,
        aws_lc_rs::default_provider(),
    ))
}

/// 证书 SHA-256 指纹（冒号分隔大写 hex），用于 UI 展示和人工核对。
pub fn fingerprint_sha256(cert_pem: &str) -> Result<String, String> {
    let pem = pem::parse(cert_pem).map_err(|error| format!("PEM 解析失败: {error}"))?;
    let digest = Sha256::digest(pem.contents());
    Ok(digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// 只复制公钥证书；本函数无法访问私钥路径，因此不会导出私钥副本。
pub fn export_cert(material: &CaMaterial, dest: &Path) -> Result<(), String> {
    fs::copy(&material.cert_path, dest).map_err(|error| format!("导出证书失败: {error}"))?;
    Ok(())
}

/// 检测当前用户是否已信任本 CA（Windows：查 CurrentUser\Root store）。
#[cfg(target_os = "windows")]
pub fn is_trusted() -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = std::process::Command::new("certutil")
        .args(["-user", "-store", "Root"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout).contains(CA_COMMON_NAME),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_trusted() -> bool {
    false
}

/// 安装 CA 到当前用户根证书 store（Windows 会弹安全警告，需用户点“是”）。
#[cfg(target_os = "windows")]
pub fn install_trusted(material: &CaMaterial) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = std::process::Command::new("certutil")
        .args(["-user", "-addstore", "Root"])
        .arg(&material.cert_path)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| format!("无法运行 certutil: {error}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(text)
    } else {
        Err(format!("certutil 执行失败（可能需要权限）: {text}"))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn install_trusted(_material: &CaMaterial) -> Result<String, String> {
    Err("当前平台暂不支持一键安装，请手动导入系统钥匙串/证书 store".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_generation_is_atomic_reloadable_and_exports_only_certificate() {
        let temp = tempfile::tempdir().unwrap();
        let material = ensure_ca(temp.path()).unwrap();
        let first_fingerprint = fingerprint_sha256(&material.cert_pem).unwrap();
        assert!(material.key_pem.contains("PRIVATE KEY"));

        let reloaded = ensure_ca(temp.path()).unwrap();
        assert_eq!(
            fingerprint_sha256(&reloaded.cert_pem).unwrap(),
            first_fingerprint
        );

        let export_dir = tempfile::tempdir().unwrap();
        let export_path = export_dir.path().join("RustForge-RootCA.cer");
        export_cert(&reloaded, &export_path).unwrap();
        let exported = fs::read_to_string(export_path).unwrap();
        assert!(exported.contains("BEGIN CERTIFICATE"));
        assert!(!exported.contains("PRIVATE KEY"));
        assert_eq!(fs::read_dir(export_dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn incomplete_ca_pair_is_never_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let (_, key_path) = ca_paths(temp.path());
        let dir = key_path.parent().unwrap();
        secure_ca_directory(dir).unwrap();
        fs::write(&key_path, "incomplete").unwrap();
        secure_private_file(&key_path).unwrap();

        let error = ensure_ca(temp.path()).err().unwrap();
        assert!(error.contains("不完整"));
        assert_eq!(fs::read_to_string(key_path).unwrap(), "incomplete");
    }

    #[cfg(unix)]
    #[test]
    fn unix_ca_permissions_are_current_user_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        ensure_ca(temp.path()).unwrap();
        let (cert_path, key_path) = ca_paths(temp.path());
        let directory_mode = fs::metadata(cert_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        let key_mode = fs::metadata(key_path).unwrap().permissions().mode();
        assert_eq!(directory_mode & 0o077, 0);
        assert_eq!(key_mode & 0o077, 0);
    }
}
