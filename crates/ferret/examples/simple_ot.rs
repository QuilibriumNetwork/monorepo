use ferret::{NetIO, FerretCOT, BlockArray, ALICE, BOB};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <party: 1 for ALICE, 2 for BOB> <port>", args[0]);
        std::process::exit(1);
    }
    
    let party: i32 = args[1].parse().expect("Party must be an integer");
    let port: i32 = args[2].parse().expect("Port must be an integer");
    
    let length = 10000;
    
    let address = if party == ALICE { None } else { Some("127.0.0.1".to_string()) };
    let io = NetIO::new(party, address, port);
    
    let ote = FerretCOT::new(party, 1, &io, true);
    
    if party == ALICE {
        let b0 = BlockArray::new(length);
        let b1 = BlockArray::new(length);
        
        println!("ALICE: Sending COT...");
        ote.send_cot(&b0, length);
        
        println!("ALICE: Sending ROT...");
        ote.send_rot(&b0, &b1, length);
        println!("ALICE: Done");
    } else {
        let br = BlockArray::new(length);
        
        let mut choices = vec![false; length as usize];
        for i in 0..length {
            choices[i as usize] = i % 2 == 0;
        }
        
        println!("BOB: Receiving COT...");
        ote.recv_cot(&br, &choices, length);
        
        println!("BOB: Receiving ROT...");
        ote.recv_rot(&br, &choices, length);
        println!("BOB: Done");
    }
}