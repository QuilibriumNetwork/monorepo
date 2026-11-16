//! The machine a node runs on, for the health report ([`Machine`]): its
//! model and CPU as an enum and numbers, and its cores, read once per
//! process, and how often its CPU throttled for heat, read with each
//! report. No name the machine's owner or vendor wrote is sent: the report
//! carries no strings. No serial number, hostname or UUID is read.

use quil_types::proto::diagnostics::{CpuVendor, MacFamily, Machine};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::OnceLock;

/// The most CPU directories read for the throttle count.
const MAX_CPU_DIRS: usize = 4096;

/// The most /proc/cpuinfo lines read for the first CPU's values.
const MAX_CPUINFO_LINES: usize = 64;

/// The machine this process runs on.
pub fn current() -> Machine {
    static FIXED: OnceLock<Machine> = OnceLock::new();
    let root = Path::new("/");
    let mut machine = *FIXED.get_or_init(|| {
        let mut machine = if cfg!(target_os = "macos") {
            from_sysctl(&sysctl)
        } else {
            from_linux(root)
        };
        machine.cpus = std::thread::available_parallelism()
            .map_or(0, |cpus| u32::try_from(cpus.get()).unwrap_or(u32::MAX));
        machine
    });
    if cfg!(target_os = "linux") {
        machine.throttle_events = throttle_events(root);
    }
    machine
}

/// A Mac's model family and numbers from its hw.model: `MacBookPro18,3`
/// is MacBook Pro, 18, 3. A name this build does not know is
/// [`MacFamily::Unknown`] with what numbers it has; nothing is
/// [`MacFamily::Unspecified`].
pub fn mac_model(hw_model: &str) -> (MacFamily, u32, u32) {
    let hw_model = hw_model.trim();
    if hw_model.is_empty() {
        return (MacFamily::Unspecified, 0, 0);
    }
    let digits = hw_model
        .find(|c: char| c.is_ascii_digit())
        .unwrap_or(hw_model.len());
    let (name, numbers) = hw_model.split_at(digits);
    let (major, minor) = numbers
        .split_once(',')
        .and_then(|(major, minor)| Some((major.parse().ok()?, minor.parse().ok()?)))
        .unwrap_or((0, 0));
    let family = match name {
        "MacBookPro" => MacFamily::MacbookPro,
        "MacBookAir" => MacFamily::MacbookAir,
        "Macmini" => MacFamily::MacMini,
        "MacStudio" => MacFamily::MacStudio,
        "MacPro" => MacFamily::MacPro,
        "iMac" => MacFamily::Imac,
        "Mac" => MacFamily::Mac,
        _ => MacFamily::Unknown,
    };
    (family, major, minor)
}

/// The CPU vendor CPUID names (`GenuineIntel`, `AuthenticAMD`); another
/// is [`CpuVendor::Unknown`], none [`CpuVendor::Unspecified`].
fn x86_vendor(id: &str) -> CpuVendor {
    match id.trim() {
        "" => CpuVendor::Unspecified,
        "GenuineIntel" => CpuVendor::Intel,
        "AuthenticAMD" => CpuVendor::Amd,
        _ => CpuVendor::Unknown,
    }
}

/// An ARM CPU's vendor from its implementer code: Apple's is 0x61.
fn arm_vendor(implementer: u32) -> CpuVendor {
    if implementer == 0x61 {
        CpuVendor::Apple
    } else {
        CpuVendor::ArmOther
    }
}

/// A number as /proc/cpuinfo or sysctl prints it: decimal, `0x` hex, or a
/// negative 32-bit value (sysctl prints hw.cpufamily signed).
fn number(text: &str) -> Option<u32> {
    let text = text.trim();
    match text.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => text
            .parse::<u32>()
            .ok()
            .or_else(|| text.parse::<i32>().ok().map(i32::cast_unsigned)),
    }
}

/// The first CPU's vendor and numbers from /proc/cpuinfo's text: x86's
/// vendor_id, cpu family, model and stepping (CPUID's), else ARM's CPU
/// implementer, part, variant and revision. Read up to the first blank
/// line only.
fn cpu_from_cpuinfo(text: &str) -> Machine {
    let mut values = std::collections::HashMap::new();
    for line in text.lines().take(MAX_CPUINFO_LINES) {
        if line.trim().is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            values.entry(key.trim()).or_insert(value.trim());
        }
    }
    let get = |key: &str| values.get(key).and_then(|value| number(value));
    let mut machine = Machine::default();
    if let Some(id) = values.get("vendor_id") {
        machine.set_cpu_vendor(x86_vendor(id));
        machine.cpu_family = get("cpu family").unwrap_or(0);
        machine.cpu_model = get("model").unwrap_or(0);
        machine.cpu_stepping = get("stepping").unwrap_or(0);
    } else if let Some(implementer) = get("CPU implementer") {
        machine.set_cpu_vendor(arm_vendor(implementer));
        machine.cpu_family = implementer;
        machine.cpu_model = get("CPU part").unwrap_or(0);
        machine.cpu_stepping =
            (get("CPU variant").unwrap_or(0) << 4) | (get("CPU revision").unwrap_or(0) & 0xf);
    }
    machine
}

/// A Mac's model, CPU and cores from its sysctl values (`read`): an
/// Intel Mac's CPUID values (machdep.cpu.*), Apple silicon's hw.cpufamily
/// and hw.cpusubfamily.
fn from_sysctl(read: &dyn Fn(&str) -> Option<String>) -> Machine {
    let value = |name: &str| read(name).as_deref().and_then(number);
    let mut machine = Machine::default();
    let (family, major, minor) = mac_model(read("hw.model").as_deref().unwrap_or_default());
    machine.set_mac_family(family);
    machine.mac_major = major;
    machine.mac_minor = minor;
    if let Some(id) = read("machdep.cpu.vendor") {
        machine.set_cpu_vendor(x86_vendor(&id));
        machine.cpu_family = value("machdep.cpu.family").unwrap_or(0);
        machine.cpu_model = value("machdep.cpu.model").unwrap_or(0);
        machine.cpu_stepping = value("machdep.cpu.stepping").unwrap_or(0);
    } else if let Some(cpu_family) = value("hw.cpufamily") {
        machine.set_cpu_vendor(CpuVendor::Apple);
        machine.cpu_family = cpu_family;
        machine.cpu_model = value("hw.cpusubfamily").unwrap_or(0);
    }
    machine.performance_cores = value("hw.perflevel0.physicalcpu");
    machine.efficiency_cores = value("hw.perflevel1.physicalcpu");
    machine
}

/// The value of the sysctl `name`, or `None` where it is unknown.
fn sysctl(name: &str) -> Option<String> {
    let output = std::process::Command::new("/usr/sbin/sysctl")
        .arg("-n")
        .arg(name)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// A Linux machine's CPU under `root`, from its /proc/cpuinfo; its model
/// names are free text and left out.
fn from_linux(root: &Path) -> Machine {
    let text = std::fs::File::open(root.join("proc/cpuinfo"))
        .map(|file| {
            BufReader::new(file)
                .lines()
                .map_while(Result::ok)
                .take(MAX_CPUINFO_LINES)
                .take_while(|line| !line.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    cpu_from_cpuinfo(&text)
}

/// The most throttled core's thermal throttle events since boot under
/// `root` (Linux on Intel CPUs), or `None` where no count is readable.
fn throttle_events(root: &Path) -> Option<u64> {
    let cpus = std::fs::read_dir(root.join("sys/devices/system/cpu")).ok()?;
    cpus.flatten()
        .take(MAX_CPU_DIRS)
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.strip_prefix("cpu")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            })
        })
        .filter_map(|entry| {
            let count = entry.path().join("thermal_throttle/core_throttle_count");
            std::fs::read_to_string(count)
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()
        })
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    fn write(root: &Path, path: &str, contents: &[u8]) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn cpu(machine: &Machine) -> (CpuVendor, u32, u32, u32) {
        (
            machine.cpu_vendor(),
            machine.cpu_family,
            machine.cpu_model,
            machine.cpu_stepping,
        )
    }

    /// Each Mac family's hw.model gives its family and numbers; a name
    /// this build does not know, or none, gives no family.
    #[test]
    fn a_mac_model_is_its_family_and_numbers() {
        for (hw_model, expected) in [
            ("MacBookPro18,3\n", (MacFamily::MacbookPro, 18, 3)),
            ("MacBookAir10,1", (MacFamily::MacbookAir, 10, 1)),
            ("Macmini9,1", (MacFamily::MacMini, 9, 1)),
            ("MacStudio1,1", (MacFamily::MacStudio, 1, 1)),
            ("MacPro7,1", (MacFamily::MacPro, 7, 1)),
            ("iMac21,1", (MacFamily::Imac, 21, 1)),
            ("Mac14,2", (MacFamily::Mac, 14, 2)),
        ] {
            assert_eq!(mac_model(hw_model), expected, "MAC-FAMILY: {hw_model}");
        }
        assert_eq!(
            mac_model("VirtualMac2,1"),
            (MacFamily::Unknown, 2, 1),
            "MAC-UNKNOWN: an unknown name keeps its numbers"
        );
        assert_eq!(mac_model("MacBook10,1"), (MacFamily::Unknown, 10, 1));
        assert_eq!(mac_model("Mac14"), (MacFamily::Mac, 0, 0));
        assert_eq!(mac_model("garbage"), (MacFamily::Unknown, 0, 0));
        assert_eq!(mac_model(" \n"), (MacFamily::Unspecified, 0, 0));
    }

    /// An x86 CPU is its CPUID vendor, family, model and stepping as
    /// /proc/cpuinfo prints them, read from the first CPU only; a vendor
    /// this build does not know is Unknown with its numbers.
    #[test]
    fn an_x86_cpu_is_its_cpuid_vendor_family_model_and_stepping() {
        let intel = "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n\
                     model\t\t: 151\nmodel name\t: 12th Gen Intel(R) Core(TM) i7-12700K\n\
                     stepping\t: 2\n\nprocessor\t: 1\nvendor_id\t: other\n";
        assert_eq!(
            cpu(&cpu_from_cpuinfo(intel)),
            (CpuVendor::Intel, 6, 151, 2),
            "CPUID-INTEL: model, not model name"
        );
        let amd = "vendor_id\t: AuthenticAMD\ncpu family\t: 25\nmodel\t\t: 33\nstepping\t: 0\n";
        assert_eq!(cpu(&cpu_from_cpuinfo(amd)), (CpuVendor::Amd, 25, 33, 0));
        let hygon = "vendor_id\t: HygonGenuine\ncpu family\t: 24\nmodel\t\t: 1\nstepping\t: 1\n";
        assert_eq!(
            cpu(&cpu_from_cpuinfo(hygon)),
            (CpuVendor::Unknown, 24, 1, 1),
            "CPUID-UNKNOWN: another vendor is Unknown"
        );
        let mac = HashMap::from([
            ("hw.model", "MacBookPro16,1\n"),
            ("machdep.cpu.vendor", "GenuineIntel\n"),
            ("machdep.cpu.family", "6\n"),
            ("machdep.cpu.model", "158\n"),
            ("machdep.cpu.stepping", "13\n"),
        ]);
        let machine = from_sysctl(&|name| mac.get(name).map(|value| value.to_string()));
        assert_eq!(cpu(&machine), (CpuVendor::Intel, 6, 158, 13));
        assert_eq!(
            (machine.performance_cores, machine.efficiency_cores),
            (None, None)
        );
        assert_eq!(
            cpu(&cpu_from_cpuinfo("")),
            (CpuVendor::Unspecified, 0, 0, 0)
        );
    }

    /// An ARM CPU on Linux is its implementer, part, variant and revision:
    /// Apple's implementer is Apple, another ARM Other.
    #[test]
    fn an_arm_cpu_is_its_implementer_part_and_revision() {
        let pi = "processor\t: 0\nBogoMIPS\t: 108.00\nCPU implementer\t: 0x41\n\
                  CPU architecture: 8\nCPU variant\t: 0x4\nCPU part\t: 0xd0b\n\
                  CPU revision\t: 1\n\nprocessor\t: 1\nCPU implementer\t: 0x61\n";
        assert_eq!(
            cpu(&cpu_from_cpuinfo(pi)),
            (CpuVendor::ArmOther, 0x41, 0xd0b, 0x41),
            "ARM-OTHER: implementer, part and 0xVR"
        );
        let asahi = "CPU implementer\t: 0x61\nCPU variant\t: 0x1\nCPU part\t: 0x23\n\
                     CPU revision\t: 1\n";
        assert_eq!(
            cpu(&cpu_from_cpuinfo(asahi)),
            (CpuVendor::Apple, 0x61, 0x23, 0x11),
            "ARM-APPLE: Apple's implementer"
        );
    }

    /// Apple silicon on macOS is its hw.cpufamily, printed signed above
    /// 2^31, and hw.cpusubfamily, with its two kinds of cores; no names.
    #[test]
    fn apple_silicon_is_its_cpu_family_subfamily_and_cores() {
        let values = HashMap::from([
            ("hw.model", "Mac14,2\n"),
            ("machdep.cpu.brand_string", "Apple M2\n"),
            ("hw.cpufamily", "-634136515\n"),
            ("hw.cpusubfamily", "2\n"),
            ("hw.perflevel0.physicalcpu", "4\n"),
            ("hw.perflevel1.physicalcpu", "4\n"),
        ]);
        let machine = from_sysctl(&|name| values.get(name).map(|value| value.to_string()));
        assert_eq!(
            (machine.mac_family(), machine.mac_major, machine.mac_minor),
            (MacFamily::Mac, 14, 2)
        );
        assert_eq!(
            cpu(&machine),
            (CpuVendor::Apple, 0xda33_d83d, 2, 0),
            "APPLE-FAMILY: a signed hw.cpufamily is its 32 bits"
        );
        assert_eq!(
            (machine.performance_cores, machine.efficiency_cores),
            (Some(4), Some(4))
        );
        let m1 = HashMap::from([
            ("hw.cpufamily", "458787763"),
            ("hw.perflevel0.physicalcpu", "8"),
            ("hw.perflevel1.physicalcpu", "2"),
        ]);
        let machine = from_sysctl(&|name| m1.get(name).map(|value| value.to_string()));
        assert_eq!(cpu(&machine), (CpuVendor::Apple, 0x1b58_8bb3, 0, 0));
        assert_eq!(
            (machine.performance_cores, machine.efficiency_cores),
            (Some(8), Some(2)),
            "MAC-CORES: performance cores are perflevel0"
        );
        assert_eq!(machine.mac_family(), MacFamily::Unspecified);
    }

    /// A Linux machine is read from its root: the first CPU's values and
    /// the most throttled core's count; no model name; nothing readable
    /// leaves every field unset.
    #[test]
    fn a_linux_machine_is_read_from_cpuinfo_and_throttle_counts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "sys/class/dmi/id/product_name", b"MS-7D25\n");
        write(
            root,
            "proc/cpuinfo",
            b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 151\n\
              stepping\t: 2\n\nprocessor\t: 1\n",
        );
        for (cpu, count) in [
            ("cpu0", "3\n"),
            ("cpu1", "7\n"),
            ("cpu2", "x"),
            ("cpufreq", "99"),
        ] {
            let path = format!("sys/devices/system/cpu/{cpu}/thermal_throttle/core_throttle_count");
            write(root, &path, count.as_bytes());
        }
        let machine = from_linux(root);
        assert_eq!(
            cpu(&machine),
            (CpuVendor::Intel, 6, 151, 2),
            "LINUX-CPU: the first CPU's values"
        );
        assert_eq!(machine.mac_family(), MacFamily::Unspecified);
        assert_eq!(
            throttle_events(root),
            Some(7),
            "THROTTLE-MOST: the most throttled core"
        );

        let bare = tempfile::tempdir().unwrap();
        assert_eq!(from_linux(bare.path()), Machine::default());
        assert_eq!(throttle_events(bare.path()), None);
    }
}
