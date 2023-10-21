
use std::any::type_name;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::net::{TcpListener, TcpStream};
use json;
use json::JsonValue;

const DEFAULT_JSON : &str = "{
    \"net_config\" : {
        \"ip\": \"127.0.0.1\",
        \"port\": 7777,
        \"key_type\": \"fixed\",
        \"key\": \"\"
    },
    \"properties\": {
        \"file_read\": true,
        \"file_write\": true,
        \"file_execute\": true
    }
}";

const CONFIG_PATH: &str = "kissas-config.json";
const MAGIC0 : u8 = 0xFE;
const MAGIC1 : u8 = 0xA7;
const CMD_PING: u8 = 0x00;
const CMD_FREAD: u8 = 0x01;
const CMD_FWRITE: u8 = 0x02;
const CMD_FEXE: u8 = 0x03;
const ACK_SEQUENCE: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
const NACK_SEQUENCE: [u8; 4] = [0xFE, 0xEE, 0xEE, 0xED];

fn log_to_console(msg : String) {
    // todo better logging
    println!("{:}", msg);
}

macro_rules! log {
    ($test:expr) => {
        log_to_console(format!($test))
    }
}

enum KeyType {
    Fixed,
    Invalid
}

fn get_key_type(config : &JsonValue) -> KeyType {
    match config["net_config"]["key_type"].as_str().unwrap() {
        "fixed" => KeyType::Fixed,
        _ => KeyType::Invalid
    }
}

fn validate_key(key_type: KeyType, key: &String, stream: &mut TcpStream) -> bool {
    match key_type {
        KeyType::Fixed => {
            if key.len() == 0 {
                return true;
            }
            let mut key_raw = vec![0u8; key.len()];
            
            match stream.read_exact(&mut key_raw) {
                Ok(_) => return key_raw == key.as_bytes(),
                Err(why) => { 
                    log!("Key retrieval failed: {why}");
                    return false;
                }
            }
        }
        KeyType::Invalid => false
    }
}

fn get_json_from_stream(stream : &mut TcpStream) -> JsonValue {
    // format is:
    //  LEN_LSB
    //  ...
    //  LEN_MSB
    //  json...
    let mut packet_size = [0u8; 4];

    match stream.read_exact(&mut packet_size) {
        Ok(_) => {
            let json_size = (packet_size[0] as usize) | 
                                   ((packet_size[1] as usize) <<  8) | 
                                   ((packet_size[2] as usize) << 16) | 
                                   ((packet_size[3] as usize) << 24);

            let mut json_payload = vec![0u8; json_size];
            match stream.read_exact(&mut json_payload) {
                Ok(_) => {
                    let json_string = String::from_utf8(json_payload).unwrap();

                    match json::parse(json_string.as_str()) {
                        Ok(json_data)  => return json_data,
                        Err(why) => {
                            log!("Failed to parse remote json: {why}");
                            log!("Rx: {json_string}");
                            return json::from("");
                        }
                    }
                },
                Err(why) => {
                    log!("Could not read json blob of size {json_size}: {why}");
                    return json::from("");
                }
            }
        },
        Err(why) => {
            log!("Could not read packet length (2 bytes): {why}");
            return json::from("");
        }
    }
}

fn handle_ping_cmd(config: &JsonValue, stream: &mut TcpStream) {
    log!("Handling ping command");
    
    // PING command does not require a key
    let _ = stream.write(&ACK_SEQUENCE);
}

fn handle_file_read_cmd(config: &JsonValue, stream: &mut TcpStream) {
    log!("Handling file read command");

    if config["properties"]["file_read"] != true {
        log!("Rejecting file read command as read property is disabled.");
        let _ = stream.write(&NACK_SEQUENCE);
        return;
    }

    match validate_key(get_key_type(config), &String::from(config["net_config"]["key"].as_str().unwrap()), stream) {
        true => {
            let request = get_json_from_stream(stream);
            // test for expected parameters
            if request["path"] == json::Null {
                let _ = stream.write(&NACK_SEQUENCE);
            } else {
                let file_path = request["path"].to_string();
                let mut file_to_read = match File::open(&file_path) {
                    Ok(file) => file,
                    Err(why) => {
                        log!("{file_path}: {why}");
                        let _ = stream.write(&NACK_SEQUENCE);
                        return;
                    }
                };

                let mut file_data = String::new();
                match file_to_read.read_to_string(&mut file_data) {
                    Ok(_) => (),
                    Err(why) => {
                        log!("{file_path}: {why}");
                        let _ = stream.write(&NACK_SEQUENCE);
                        return;
                    }
                }

                let file_read_response = json::object!{
                    path: file_path,
                    data: file_data.as_bytes()
                };

                let json_response = json::stringify(file_read_response);
                if stream.write(&ACK_SEQUENCE).is_err() {
                    log!("Failed to write ACK_SEQUENCE");
                    return;
                }
                
                let len_bytes: [u8; 4] = [
                    ((json_response.as_bytes().len() >> 0) & 0xFF) as u8,
                    ((json_response.as_bytes().len() >> 8) & 0xFF) as u8,
                    ((json_response.as_bytes().len() >> 16) & 0xFF) as u8,
                    ((json_response.as_bytes().len() >> 24) & 0xFF) as u8
                ];
                
                if stream.write(&len_bytes).is_err() {
                    log!("Failed to write response json length");
                    return;
                }
                
                if stream.write(json_response.as_bytes()).is_err() {
                    log!("Failed to write json {json_response}");
                    return;
                }

                let mut ack_response = [0u8; ACK_SEQUENCE.len()];
                if stream.read_exact(&mut ack_response).is_err() || ack_response != ACK_SEQUENCE {
                    log!("Failed to get ACK response to JSON transfer.");
                    return;
                }

                log!("Successfully transfered {json_response}");
            }
        },

        false => {
            let _ = stream.write(&NACK_SEQUENCE);
        }
    }
}

fn handle_file_write_cmd(config: &JsonValue, stream: &mut TcpStream) {
    log!("Handling file write command");
}

fn handle_file_execute_cmd(config: &JsonValue, stream: &mut TcpStream) {
    log!("Handling file execute command");
}

fn handle_incoming_stream(config: &JsonValue, stream : &mut TcpStream) {
    // payload format:
    // byte0 -> MAGIC0
    // byte1 -> MAGIC1
    // byte2 -> CMD type

    let mut command_buf = [0 as u8; 3];
    let result = stream.read_exact(&mut command_buf);

    match result {
        Ok(_) => (),
        Err(why) => {
            log!("Stream failed to read: {why}");
            return;
        }
    }

    let magic0 = command_buf[0];
    match magic0 {
        MAGIC0 => (),
        _ => {
            log!("Unexpected or unaligned TCP byte 0 - {magic0}");
            return;
        }
    }

    let magic1 = command_buf[1];
    match magic1 {
        MAGIC1 => (),
        _ => {
            log!("Unexpected or unaligned TCP byte 1 - {magic1}");
            return;
        }
    }

    let cmd = command_buf[2];
    match cmd {
        CMD_PING => {
            return handle_ping_cmd(config, stream);
        },

        CMD_FREAD => {
            return handle_file_read_cmd(config, stream);
        },

        CMD_FWRITE => {
            return handle_file_write_cmd(config, stream);
        },

        CMD_FEXE => {
            return handle_file_execute_cmd(config, stream);
        },

        _ => {
            log!("Unexpected or unaligned TCP byte 2(CMD) - {cmd}");
            return;
        }
    }
    
}

fn client_connect(config : &JsonValue) -> Result<TcpStream, std::io::Error> {
    let server = format!("{}:{}", config["net_config"]["ip"], config["net_config"]["port"]);
    log!("Attempting connection to {server}");
    
    TcpStream::connect(server)
}

fn client_send_key(config: &JsonValue, stream : &mut TcpStream) -> Result<usize, std::io::Error> {
    match get_key_type(config) {
        KeyType::Fixed => {
            let key = config["net_config"]["key"].to_string();
            log!("Sending fixed keytype {key}");
            
            if key.len() == 0 {
                return Ok(0);
            }

            stream.write(&key.as_bytes())
        },

        KeyType::Invalid => {
            log!("Invalid key type detected in config.");
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Bad key type"));
        }
    }
}

fn handle_client_write(args: &Vec<String>, config : &JsonValue) {
    if args.len() != 4 {
        print_client_usages();
        return;
    }
}

fn handle_client_read(args: &Vec<String>, config : &JsonValue) {
    if args.len() != 4 {
        print_client_usages();
        return;
    }

    let remote_source_file = &args[2];
    let local_destination_file = &args[3];

    match client_connect(config) {
        Ok(mut stream) => {
            let read_command = [MAGIC0, MAGIC1, CMD_FREAD];
            
            if stream.write(&read_command).is_err() {
                log!("Failed to send read command");
                return;
            }

            if client_send_key(config, &mut stream).is_err() {
                log!("Failed to send key");
                return;
            }

            // generate json file for read request
            let json_string = format!("{{\"path\":\"{remote_source_file}\"}}");
            let mut json_string_len = [
                ((json_string.as_bytes().len() >> 0) & 0xFF) as u8,
                ((json_string.as_bytes().len() >> 8) & 0xFF) as u8,
                ((json_string.as_bytes().len() >> 16) & 0xFF) as u8,
                ((json_string.as_bytes().len() >> 24) & 0xFF) as u8
            ];

            if stream.write(&json_string_len).is_err() {
                log!("Failed to send json request length");
                return;
            }

            if stream.write(&json_string.as_bytes()).is_err() {
                log!("Failed to send json request");
                return;
            }

            let mut ack_response = [0u8; 4];
            if stream.read_exact(&mut ack_response).is_err() {
                log!("Failed to read ack/nack response");
                return;
            }

            if ack_response != ACK_SEQUENCE {
                log!("Bad ACK response");
                if ack_response == NACK_SEQUENCE {
                    log!("(NACK)");
                }
                return;
            }

            if stream.read_exact(&mut json_string_len).is_err() {
                log!("Failed to read json response length");
                return;
            }

            let response_len = (json_string_len[0] as usize) |
                                   (json_string_len[1] as usize) << 8 |
                                   (json_string_len[2] as usize) << 16 |
                                   (json_string_len[3] as usize) << 24;

            let mut json_response : Vec<u8> = vec![0u8; response_len];
            
            if stream.read_exact(&mut json_response).is_err() {
                log!("Failed to read json response of length {response_len}");
                return;
            }

            let _ = stream.write(&ACK_SEQUENCE);

            let json_response_string = String::from_utf8(json_response.clone()).unwrap();
            log!("response: {json_response_string}");

            // first, save off raw json for utility reasons
            let mut file_raw = match File::options().write(true).create(true).truncate(true).open(format!("{local_destination_file}.raw.json")) {
                Ok(file) => file,
                Err(why) => {
                    log!("Failed to open {local_destination_file}.raw.json for writing!");
                    return;
                }
            };

            if file_raw.write(&json_response).is_err() {
                log!("Failed to write json raw log file.");
                return;
            }
            
            // convert json string to object
            let json_object = json::parse(&json_response_string.as_str());
            if json_object.is_err() {
                log!("Failed to parse json response:");
                return;
            }

            let json_object = json_object.unwrap();
            let data = match &json_object["data"] {
                JsonValue::Array(json_array) => {
                    let mut vectorized : Vec<u8> = vec![];
                    for element in json_array {
                        match element {
                            JsonValue::Number(value) => {
                                vectorized.push(value.to_string().parse::<i32>().unwrap() as u8);
                            },
                            _ => {
                                log!("Invalid seuquence, skipping");
                            }
                        }
                    }

                    vectorized
                },
                _ => "UNSUPPORTED\n".to_string().into()
            };

            let mut file = match File::options().write(true).create(true).truncate(true).open(local_destination_file) {
                Ok(file) => file,
                Err(why) => {
                    log!("Failed to open {local_destination_file} for writing: {why}");
                    return;
                }
            };

            let _ = file.write(&data);
        },
        Err(why) => {
            log!("Failed to open stream to host.");
            return;
        }
    }
}

fn handle_client_execute(args: &Vec<String>, config : &JsonValue) {
    if args.len() != 3 {
        print_client_usages();
        return;
    }
}

fn handle_client_ping(args: &Vec<String>, config : &JsonValue) {
    let ping_command = [MAGIC0, MAGIC1, CMD_PING];

    match client_connect(config) {
        Ok(mut stream) => {
            match stream.write(&ping_command) {
                Ok(_) => {
                    let mut ack_packet = [0u8; ACK_SEQUENCE.len()];
                    match stream.read(&mut ack_packet) {
                        Ok(_) => {
                            match ack_packet {
                                ACK_SEQUENCE => log!("Ping successful!"),
                                NACK_SEQUENCE => log!("Received NACK from server"),
                                _ => log!("received unknown sequence from ping command.")
                            }
                        },
                        Err(why) => {
                            log!("Failed to read ACK: {why}");
                        }
                    }
                },
                Err(why) => {
                    log!("Failed to write ping command to server: {why}");
                }
            } 
        },
        Err(why) => {
            log!("Failed to connect to server: {why}");
        }
    }
}

fn print_client_usages() {
    println!("Invalid command. Usages:");
    println!("No parameters: start a server using {CONFIG_PATH} settings.");
    println!("-w local_source_file remote_destination_file [{CONFIG_PATH} is used for target server] | write a file");
    println!("-r remote_source_file local_destination_file [{CONFIG_PATH} is used for target server] | read a file");
    println!("-x remote_file [{CONFIG_PATH} is used for target server] | execute a script");
    println!("-p [{CONFIG_PATH} is used for target server] | ping the server")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let path = Path::new(CONFIG_PATH);
    let path_uni = path.display();
    let config;

    let opt_file = File::open(path);
    let mut run = true;

     match opt_file {
        Err(why) => {
            log!("{path_uni} - {why}, using default config settings.");
            config = json::parse(DEFAULT_JSON);
        },
        Ok(mut file) => {
            log!("Loading config from {path_uni}...");
            let mut file_contents = String::new(); 
            match file.read_to_string(&mut file_contents) {
                Ok(_) => config = json::parse(&file_contents),
                Err(why) => {
                    log!("Could not read {path_uni} due to {why}");
                    config = json::parse(DEFAULT_JSON);
                }
            }
        }
    };

    let agent_settings = match config {
        Ok(json_object) => json_object,
        Err(why) => {
            log!("Could not parse config json: {why}");
            panic!("Failed to load agent config json");
        }
    };

    log!("KISSAS Settings: {agent_settings}");

    if args.len() > 1 {
        let client_command = &args[1];

        match client_command.as_str() {
            "-w" | "-W" => return handle_client_write(&args, &agent_settings),
            "-r" | "-R" => return handle_client_read(&args, &agent_settings),
            "-x" | "-X" | "-e" | "-E" => return handle_client_execute(&args, &agent_settings),
            "-p" | "-P" => return handle_client_ping(&args, &agent_settings),
            _ => {
                print_client_usages();
                return;
            }
        }
    }


    let listener = match TcpListener::bind(format!("{}:{}", agent_settings["net_config"]["ip"], agent_settings["net_config"]["port"])) {
        Ok(tcp_listener) => tcp_listener,
        Err(why) => {
            log!("TCPListener failed: {why}");
            return;
        }
    };

    while run {
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => handle_incoming_stream(&agent_settings, &mut stream),
                Err(why) => log!("Failed to handle incoming stream: {why}")
            }
        }

        // don't hog the CPU
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

}
