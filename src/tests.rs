use super::*;

#[test]
fn basic_test() {
    // generate the data
    let ssid = "test_ssid".to_string();
    let pass = "test_pass".to_string();

    let encryption_key = "abcdefghijklmnop".to_string();
    let integrity_key = "jkl;311234;9dj;2".to_string();
    let send_flag = false;
    let id = 0;
    let possible_loss = FecLoss::L40p;

    if let Ok(packets) = generate_packets(
        ssid,
        pass,
        encryption_key,
        integrity_key,
        send_flag,
        id,
        possible_loss,
    ) {
        // repeatedly send the packets
        eprintln!("{:?}", packets);
    }
}
