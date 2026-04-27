use anyhow::{bail, Context, Result};
use goblin::elf::{section_header, sym::Sym, Elf};
use scroll::{ctx::SizeWith, Pwrite};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const INIT_MODULE_SYSCALL_NR: libc::c_long = 105;

#[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
const INIT_MODULE_SYSCALL_NR: libc::c_long = libc::SYS_init_module as libc::c_long;

struct KptrGuard {
    original: String,
}

impl KptrGuard {
    fn new() -> Result<Self> {
        let path = "/proc/sys/kernel/kptr_restrict";
        let original = fs::read_to_string(path).context("read kptr_restrict")?;
        fs::write(path, "0\n").context("temporarily relax kptr_restrict")?;
        Ok(Self { original })
    }
}

impl Drop for KptrGuard {
    fn drop(&mut self) {
        let _ = fs::write("/proc/sys/kernel/kptr_restrict", self.original.as_bytes());
    }
}

#[derive(Debug)]
struct CommonArgs {
    module_path: PathBuf,
    module_name: String,
    params: String,
    dmesg_lines: usize,
}

#[derive(Debug)]
struct AdbArgs {
    adb_bin: PathBuf,
    serial: Option<String>,
    local_device_loader: PathBuf,
    remote_dir: String,
}

#[derive(Debug)]
enum RunMode {
    Local,
    Adb(AdbArgs),
}

fn normalize_symbol_name(symbol: &str) -> &str {
    symbol
        .find('$')
        .or_else(|| symbol.find(".llvm."))
        .map(|pos| &symbol[..pos])
        .unwrap_or(symbol)
}

fn kernel_symbol_map() -> Result<HashMap<String, u64>> {
    let _guard = KptrGuard::new()?;
    let reader = BufReader::new(File::open("/proc/kallsyms").context("open /proc/kallsyms")?);
    let mut map = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<_> = line.split_whitespace().collect();

        if parts.len() != 3 {
            continue;
        }

        let Ok(addr) = u64::from_str_radix(parts[0], 16) else {
            continue;
        };

        let name = normalize_symbol_name(parts[2]).to_owned();
        map.entry(name).or_insert(addr);
    }

    Ok(map)
}

fn resolve_module_symbols(buffer: &mut Vec<u8>) -> Result<Vec<String>> {
    let elf = Elf::parse(buffer).context("parse module ELF")?;
    let ctx = *elf.syms.ctx();
    let symbols = kernel_symbol_map()?;
    let mut unresolved: HashMap<String, (Sym, usize)> = HashMap::new();

    for (index, sym) in elf.syms.iter().enumerate() {
        if index == 0 || sym.st_shndx != section_header::SHN_UNDEF as usize {
            continue;
        }

        let Some(name) = elf.strtab.get_at(sym.st_name) else {
            continue;
        };

        let offset = elf.syms.offset() + index * Sym::size_with(elf.syms.ctx());
        unresolved.insert(name.to_owned(), (sym, offset));
    }

    for (name, addr) in &symbols {
        if let Some((mut sym, offset)) = unresolved.remove(name) {
            sym.st_shndx = section_header::SHN_ABS as usize;
            sym.st_value = *addr;
            buffer
                .pwrite_with(sym, offset, ctx)
                .with_context(|| format!("patch symbol {name}"))?;
        }

        if unresolved.is_empty() {
            break;
        }
    }

    let mut remaining: Vec<_> = unresolved.into_keys().collect();
    remaining.sort();
    Ok(remaining)
}

fn init_module_syscall(buffer: &[u8], params: &CString) -> Result<()> {
    let rc =
        unsafe { libc::syscall(INIT_MODULE_SYSCALL_NR, buffer.as_ptr(), buffer.len(), params.as_ptr()) };

    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("init_module syscall failed");
    }

    Ok(())
}

fn relevant_dmesg(module_name: &str, limit: usize) -> Result<Vec<String>> {
    let output = Command::new("dmesg")
        .output()
        .context("run dmesg to collect kernel logs")?;

    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines: Vec<String> = text
        .lines()
        .filter(|line| {
            line.contains(module_name)
                || line.contains("Unknown symbol")
                || line.contains("unknown symbol")
                || line.contains("init_module")
        })
        .map(ToOwned::to_owned)
        .collect();

    if lines.len() > limit {
        lines = lines.split_off(lines.len() - limit);
    }

    Ok(lines)
}

fn load_module_from_path(path: &Path, params: &str) -> Result<()> {
    let mut buffer =
        fs::read(path).with_context(|| format!("read module {}", path.display()))?;
    let unresolved = resolve_module_symbols(&mut buffer)?;
    if !unresolved.is_empty() {
        eprintln!("warning: {} unresolved symbols remain:", unresolved.len());
        for symbol in &unresolved {
            eprintln!("  {symbol}");
        }
    }

    let params = CString::new(params).context("module params contain NUL byte")?;
    init_module_syscall(&buffer, &params)
}

fn shell_escape(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn usage(program: &str) {
    eprintln!(
        "Usage:
  {program} [--name MODULE_NAME] [--dmesg-lines N] <module.ko> [module params...]
  {program} --adb-run [--serial SERIAL] [--adb-bin ADB] [--device-loader PATH] [--remote-dir DIR] \\
            [--name MODULE_NAME] [--dmesg-lines N] <module.ko> [module params...]"
    );
}

fn parse_args() -> Result<(RunMode, CommonArgs)> {
    let args: Vec<String> = std::env::args().collect();
    let program = args.first().map(String::as_str).unwrap_or("hook-loader");

    let mut module_path: Option<PathBuf> = None;
    let mut module_name: Option<String> = None;
    let mut params = String::new();
    let mut dmesg_lines = 80usize;
    let mut adb_run = false;
    let mut serial = None;
    let mut adb_bin = PathBuf::from("adb");
    let mut local_device_loader =
        PathBuf::from("target/aarch64-linux-android/release/hook-loader");
    let mut remote_dir = "/data/local/tmp/hook_loader".to_owned();
    let mut i = 1usize;

    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                i += 1;
                if i >= args.len() {
                    usage(program);
                    bail!("--name requires a value");
                }
                module_name = Some(args[i].clone());
            }
            "--dmesg-lines" => {
                i += 1;
                if i >= args.len() {
                    usage(program);
                    bail!("--dmesg-lines requires a value");
                }
                dmesg_lines = args[i]
                    .parse::<usize>()
                    .with_context(|| format!("invalid dmesg line count: {}", args[i]))?;
            }
            "--adb-run" => {
                adb_run = true;
            }
            "--serial" => {
                i += 1;
                if i >= args.len() {
                    usage(program);
                    bail!("--serial requires a value");
                }
                serial = Some(args[i].clone());
            }
            "--adb-bin" => {
                i += 1;
                if i >= args.len() {
                    usage(program);
                    bail!("--adb-bin requires a value");
                }
                adb_bin = PathBuf::from(&args[i]);
            }
            "--device-loader" => {
                i += 1;
                if i >= args.len() {
                    usage(program);
                    bail!("--device-loader requires a value");
                }
                local_device_loader = PathBuf::from(&args[i]);
            }
            "--remote-dir" => {
                i += 1;
                if i >= args.len() {
                    usage(program);
                    bail!("--remote-dir requires a value");
                }
                remote_dir = args[i].clone();
            }
            "--help" | "-h" => {
                usage(program);
                std::process::exit(0);
            }
            _ => {
                module_path = Some(PathBuf::from(&args[i]));
                i += 1;
                if i < args.len() {
                    params = args[i..].join(" ");
                }
                break;
            }
        }
        i += 1;
    }

    let module_path = module_path.unwrap_or_else(|| PathBuf::from("hook_module.ko"));
    let module_name = module_name.unwrap_or_else(|| {
        module_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("hook_module")
            .to_owned()
    });

    let mode = if adb_run {
        if cfg!(target_os = "android") {
            bail!("--adb-run is only available in host builds");
        }
        RunMode::Adb(AdbArgs {
            adb_bin,
            serial,
            local_device_loader,
            remote_dir,
        })
    } else {
        RunMode::Local
    };

    Ok((
        mode,
        CommonArgs {
            module_path,
            module_name,
            params,
            dmesg_lines,
        },
    ))
}

fn adb_command(adb: &AdbArgs) -> Command {
    let mut command = Command::new(&adb.adb_bin);
    if let Some(serial) = &adb.serial {
        command.arg("-s").arg(serial);
    }
    command
}

fn run_adb(adb: &AdbArgs, description: &str, args: &[String]) -> Result<Output> {
    let output = adb_command(adb)
        .args(args)
        .output()
        .with_context(|| format!("run adb for {description}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "adb {} failed (status {}): stdout=`{}` stderr=`{}`",
            description,
            output.status,
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(output)
}

fn run_adb_mode(adb: AdbArgs, common: &CommonArgs) -> Result<()> {
    let loader_name = adb
        .local_device_loader
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("hook-loader");
    let module_name = common
        .module_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("hook_module.ko");
    let remote_loader = format!("{}/{}", adb.remote_dir, loader_name);
    let remote_module = format!("{}/{}", adb.remote_dir, module_name);
    let remote_command = format!(
        "{} --name {} --dmesg-lines {} {} {}",
        shell_escape(&remote_loader),
        shell_escape(&common.module_name),
        common.dmesg_lines,
        shell_escape(&remote_module),
        shell_escape(&common.params)
    );
    let su_command = format!(
        "mkdir -p {dir} && chmod 755 {loader} && chmod 644 {module} && {cmd}",
        dir = shell_escape(&adb.remote_dir),
        loader = shell_escape(&remote_loader),
        module = shell_escape(&remote_module),
        cmd = remote_command,
    );

    if !adb.local_device_loader.exists() {
        bail!(
            "device loader binary not found: {}",
            adb.local_device_loader.display()
        );
    }
    if !common.module_path.exists() {
        bail!("module file not found: {}", common.module_path.display());
    }

    eprintln!("[*] adb push loader: {}", adb.local_device_loader.display());
    run_adb(
        &adb,
        "push loader",
        &[
            "push".to_owned(),
            adb.local_device_loader.display().to_string(),
            remote_loader.clone(),
        ],
    )?;

    eprintln!("[*] adb push module: {}", common.module_path.display());
    run_adb(
        &adb,
        "push module",
        &[
            "push".to_owned(),
            common.module_path.display().to_string(),
            remote_module.clone(),
        ],
    )?;

    eprintln!("[*] adb shell su -c {}", su_command);
    let output = run_adb(
        &adb,
        "remote loader execution",
        &[
            "shell".to_owned(),
            format!("su -c {}", shell_escape(&su_command)),
        ],
    )?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.trim().is_empty() {
        println!("{stdout}");
    }
    if !stderr.trim().is_empty() {
        eprintln!("{stderr}");
    }

    Ok(())
}

fn run_local_mode(common: &CommonArgs) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("must run as root");
    }

    eprintln!("[*] loading module: {}", common.module_path.display());
    if !common.params.is_empty() {
        eprintln!("[*] params: {}", common.params);
    }

    match load_module_from_path(&common.module_path, &common.params) {
        Ok(()) => {
            eprintln!("[+] module loaded successfully");
            Ok(())
        }
        Err(err) => {
            eprintln!("[-] module load failed: {err:#}");
            let logs = relevant_dmesg(&common.module_name, common.dmesg_lines)?;
            if logs.is_empty() {
                eprintln!("[-] no relevant dmesg lines found for {}", common.module_name);
            } else {
                eprintln!("[*] relevant dmesg:");
                for line in logs {
                    eprintln!("{line}");
                }
            }
            Err(err)
        }
    }
}

fn main() -> Result<()> {
    let (mode, common) = parse_args()?;

    match mode {
        RunMode::Local => run_local_mode(&common),
        RunMode::Adb(adb) => run_adb_mode(adb, &common),
    }
}
