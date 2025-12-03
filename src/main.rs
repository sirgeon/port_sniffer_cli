mod core;

fn print_usage(program_name: &str) {
    println!("Usage: {} [command] [arguments]", program_name);
    println!(" -h, --help\tDisplay this help message");
    println!(" -v, --version\tDisplay the version of this program");
    println!(" -s, --scan\tScan an IP address. Usage: -s [IPv4 Address]");
    println!(" -p, --ports\tSpecify ports to scan. Usage: -p [PORT1,PORT2,...]");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 1 {
        eprintln!(
            "Error: You need to specify a command to run. Run -h or --help for more information."
        );
        std::process::exit(1);
    }

    match args[1].as_str() {
        "-h" | "--help" => print_usage(&args[0]),
        "-v" | "--version" => println!("Version: {}", env!("CARGO_PKG_VERSION")),
        "-s" | "--scan" => {
            if args.len() == 2 {
                print_usage(&args[0]);
                std::process::exit(1);
            }

            let ip = &args[2];
            let mut ports: Option<Vec<u16>> = None;

            // Check for ports parameter
            if args.len() > 4 && (args[3] == "-p" || args[3] == "--ports") {
                ports = Some(parse_ports(&args[4]));
            }

            core::scan_ip::scan(ip, ports);
        }
        _ => {
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }
}

fn parse_ports(ports_str: &str) -> Vec<u16> {
    ports_str
        .split(',')
        .filter_map(|p| p.trim().parse::<u16>().ok())
        .collect()
}
