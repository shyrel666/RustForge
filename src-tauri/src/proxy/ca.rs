//! CA 证书管理：生成自签名根 CA（rcgen 0.14）、持久化、导出、
//! Windows 信任安装/检测。CA 私钥只存在本机 app_data_dir，不上传任何位置。

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, date_time_ymd,
};
use hudsucker::rustls::crypto::aws_lc_rs;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// CA 证书 CN，Windows 证书管理器里按这个名字找
pub const CA_COMMON_NAME: &str = "RustForge MITM CA";

/// 磁盘上的 CA 材料（PEM）。私钥文件固定在 cert_path 同目录，不外传
pub struct CaMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_path: PathBuf,
}

fn ca_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join("ca").join("rustforge-ca.cer"), dir.join("ca").join("rustforge-ca.key"))
}

/// 加载已有 CA；不存在则生成新的自签名根 CA 并写入磁盘
pub fn ensure_ca(app_data_dir: &Path) -> Result<CaMaterial, String> {
    let (cert_path, key_path) = ca_paths(app_data_dir);
    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path).map_err(|e| e.to_string())?;
        let key_pem = std::fs::read_to_string(&key_path).map_err(|e| e.to_string())?;
        return Ok(CaMaterial { cert_pem, key_pem, cert_path });
    }

    let dir = cert_path.parent().ok_or("CA 目录解析失败")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;

    // rcgen 0.14：参数填好后用新生成的密钥自签
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, "RustForge (Authorized Testing Only)");
    params.distinguished_name = dn;
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2035, 12, 31);

    let key_pair = KeyPair::generate().map_err(|e| format!("生成 CA 密钥失败: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("自签 CA 证书失败: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    std::fs::write(&cert_path, &cert_pem).map_err(|e| e.to_string())?;
    std::fs::write(&key_path, &key_pem).map_err(|e| e.to_string())?;

    Ok(CaMaterial { cert_pem, key_pem, cert_path })
}

/// 从 PEM 材料构建 hudsucker 的证书颁发机构（内含站点证书缓存）
pub fn build_authority(material: &CaMaterial) -> Result<RcgenAuthority, String> {
    let key_pair =
        KeyPair::from_pem(&material.key_pem).map_err(|e| format!("CA 私钥解析失败: {e}"))?;
    let issuer = Issuer::from_ca_cert_pem(&material.cert_pem, key_pair)
        .map_err(|e| format!("CA 证书解析失败: {e}"))?;
    Ok(RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider()))
}

/// 证书 SHA-256 指纹（冒号分隔大写 hex），用于 UI 展示和人工核对
pub fn fingerprint_sha256(cert_pem: &str) -> Result<String, String> {
    let pem = pem::parse(cert_pem).map_err(|e| format!("PEM 解析失败: {e}"))?;
    let digest = Sha256::digest(pem.contents());
    Ok(digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// 把 CA 证书复制到目标路径（导出给用户安装）
pub fn export_cert(material: &CaMaterial, dest: &Path) -> Result<(), String> {
    std::fs::copy(&material.cert_path, dest)
        .map_err(|e| format!("导出证书失败: {e}"))?;
    Ok(())
}

/// 检测当前用户是否已信任本 CA（Windows：查 CurrentUser\Root store）
#[cfg(target_os = "windows")]
pub fn is_trusted() -> bool {
    let output = std::process::Command::new("certutil")
        .args(["-user", "-store", "Root"])
        .output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.contains(CA_COMMON_NAME)
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_trusted() -> bool {
    false
}

/// 安装 CA 到当前用户根证书 store（Windows 会弹安全警告，需用户点"是"——人在回路）
/// 返回 certutil 输出，便于前端展示结果
#[cfg(target_os = "windows")]
pub fn install_trusted(material: &CaMaterial) -> Result<String, String> {
    let output = std::process::Command::new("certutil")
        .args(["-user", "-addstore", "Root"])
        .arg(&material.cert_path)
        .output()
        .map_err(|e| format!("无法运行 certutil: {e}"))?;
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
