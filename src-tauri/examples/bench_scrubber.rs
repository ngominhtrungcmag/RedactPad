#[cfg(target_os = "macos")]
mod macos {
    use std::{
        env,
        fs::{self, File, OpenOptions},
        io::{self, Write},
        mem::{self, MaybeUninit},
        path::Path,
        process::Command,
        time::Instant,
    };

    use redactpad_lib::scrubber::{export_file, open_input_file, ExportJob, ExportOutcome};

    const SIZE: usize = 500 * 1024 * 1024;
    const RECORD: &[u8] = b"INFO worker heartbeat complete\r\nDEBUG password=synthetic\r\n";

    fn generate(path: &Path) -> io::Result<()> {
        let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
        let chunk = RECORD.repeat(1024);
        for _ in 0..SIZE / chunk.len() {
            file.write_all(&chunk)?;
        }
        file.write_all(&chunk[..SIZE % chunk.len()])?;
        file.sync_all()
    }

    fn memory() -> (u64, u64) {
        extern "C" {
            static mach_task_self_: libc::mach_port_t;
        }
        let mut info = MaybeUninit::<libc::mach_task_basic_info>::uninit();
        let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
        let status = unsafe {
            libc::task_info(
                mach_task_self_,
                libc::MACH_TASK_BASIC_INFO as libc::task_flavor_t,
                info.as_mut_ptr().cast(),
                &mut count,
            )
        };
        assert_eq!(status, libc::KERN_SUCCESS);
        assert_eq!(count, libc::MACH_TASK_BASIC_INFO_COUNT);
        let info = unsafe { info.assume_init() };
        let mut usage: libc::rusage = unsafe { mem::zeroed() };
        assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) }, 0);
        (
            info.resident_size,
            info.resident_size_max.max(usage.ru_maxrss as u64),
        )
    }

    fn measure(input: &Path, output: &Path) -> io::Result<()> {
        assert_eq!(fs::metadata(input)?.len(), SIZE as u64);
        let session = open_input_file(input).expect("open benchmark fixture");
        let (baseline, _) = memory();
        let timer = Instant::now();
        let outcome = export_file(&session, output, &ExportJob::new());
        let elapsed = timer.elapsed().as_secs_f64();
        let (_, peak) = memory();
        let growth = peak.saturating_sub(baseline);
        println!("elapsed_seconds={elapsed:.9} baseline_bytes={baseline} peak_bytes={peak} growth_bytes={growth}");
        assert_eq!(outcome, ExportOutcome::Published);
        assert!(elapsed <= 20.0, "elapsed limit exceeded");
        assert!(growth <= 64 * 1024 * 1024, "peak RSS growth limit exceeded");
        Ok(())
    }

    pub fn run() -> io::Result<()> {
        let args: Vec<_> = env::args_os().skip(1).collect();
        match args.as_slice() {
            [command, path] if command == "--generate" => generate(Path::new(path)),
            [command, input, output] if command == "--measure" => {
                measure(Path::new(input), Path::new(output))
            }
            [] => {
                let work = tempfile::tempdir()?;
                let input = work.path().join("synthetic.log");
                let output = work.path().join("redacted.log");
                generate(&input)?;
                let status = Command::new(env::current_exe()?)
                    .arg("--measure")
                    .arg(&input)
                    .arg(&output)
                    .status()?;
                assert!(status.success(), "fresh benchmark process failed");
                assert!(File::open(output)?.metadata()?.len() > SIZE as u64);
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "use --generate <path> or --measure <input> <output>",
            )),
        }
    }
}

#[cfg(target_os = "macos")]
fn main() -> std::io::Result<()> {
    macos::run()
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("bench_scrubber requires macOS");
}
