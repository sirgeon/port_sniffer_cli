use std::net::TcpStream;
use std::sync::{ Arc, Mutex };
use std::thread;
use std::time::{ Duration, Instant };
use std::io::Write;

pub fn scan(ip: &str, ports_to_scan: Option<Vec<u16>>) {
    let ip = ip.to_string();
    let open_ports = Arc::new(Mutex::new(Vec::new()));

    // specified ports or all ports (default)
    //
    // if ports_to_scan is None, scan all ports from 1 to 65535
    // if ports_to_scan is Some, scan only the specified ports
    let ports_vec = ports_to_scan.clone().unwrap_or((1..65535).collect::<Vec<u16>>());
    let total_ports = ports_vec.len();
    let completed = Arc::new(Mutex::new(0));
    let start_time = Instant::now();

    // set up worker pool - use number of CPUs for optimal performance
    let num_threads = thread
        ::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(8);

    if let Some(port_list) = ports_to_scan {
        println!(
            "Port sniffer CLI | Starting scan of {} with {} threads | Scanning {} specific ports",
            ip,
            num_threads,
            port_list.len()
        );
    } else {
        println!("Port sniffer CLI | Starting scan of {} with {} threads", ip, num_threads);
    }

    rayon::ThreadPoolBuilder
        ::new()
        .num_threads(num_threads)
        .build()
        .unwrap()
        .scope(|s| {
            let batch_size = 1000;
            let port_range: Vec<Vec<u16>> = ports_vec
                .chunks(batch_size)
                .map(|chunk| chunk.to_vec())
                .collect();

            for batch in port_range {
                let ip = ip.clone();
                let open_ports = Arc::clone(&open_ports);
                let completed = Arc::clone(&completed);
                let start_time = start_time;

                s.spawn(move |_| {
                    let mut batch_open_ports = Vec::new();

                    for port in batch {
                        let addr = format!("{}:{}", ip, port);
                        match
                            TcpStream::connect_timeout(
                                &addr.parse().unwrap(),
                                Duration::from_millis(500)
                            )
                        {
                            Ok(_) => batch_open_ports.push(port),
                            Err(_) => {}
                        }

                        let mut completed_count = completed.lock().unwrap();
                        *completed_count += 1;

                        if *completed_count % 100 == 0 || *completed_count == total_ports {
                            let percentage =
                                ((*completed_count as f64) / (total_ports as f64)) * 100.0;
                            let elapsed_time = start_time.elapsed();
                            let time_per_port =
                                elapsed_time.as_secs_f64() / (*completed_count as f64);
                            let remaining_ports = total_ports - *completed_count;
                            let remaining_time_secs = (time_per_port *
                                (remaining_ports as f64)) as u64;

                            // carriage return instead of clearing screen for smoother updates
                            print!(
                                "\r{:.1}% complete. ETA: {}m {}s | Ports checked: {}     ",
                                percentage,
                                remaining_time_secs / 60,
                                remaining_time_secs % 60,
                                *completed_count
                            );
                            let _ = std::io::stdout().flush();
                        }
                    }

                    if !batch_open_ports.is_empty() {
                        let mut all_open_ports = open_ports.lock().unwrap();
                        all_open_ports.extend(batch_open_ports);
                    }
                });
            }
        });

    // end of scope, all threads will be joined here
    let mut final_open_ports = open_ports.lock().unwrap().clone();
    final_open_ports.sort();

    let elapsed_time = start_time.elapsed();
    println!(
        "\nScan completed in {}m {}s",
        elapsed_time.as_secs() / 60,
        elapsed_time.as_secs() % 60
    );

    if final_open_ports.is_empty() {
        println!("No open ports found.");
    } else {
        println!("STATE\tPORT\tPROTOCOL");
        for port in &final_open_ports {
            println!("OPEN\t{}\tTCP", port);
        }
        println!("\nFound {} open ports", final_open_ports.len());
    }
}
