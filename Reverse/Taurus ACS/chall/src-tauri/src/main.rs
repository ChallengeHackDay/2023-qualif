#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::str::from_utf8;

fn get_true_password() -> String {
    let mut password = [80, 36, 85, 36, 97, 105, 72, 96, 91, 32, 93, 35, 76, 100, 26, 32, 87, 79, 26, 37, 72, 93, 98, 79, 86, 33, 30, 37, 26, 32, 87];

    for i in 0..password.len() {
        if i % 2 == 0 {
            password[i] = (password[i] + 23) % 128;
        } else {
            password[i] = (password[i] + 16) % 128;
        }
    }

    from_utf8(&password).unwrap().to_string()
}

#[tauri::command]
fn check(username: &str, password: &str) -> String {
    let mut true_username_rev = [114, 48, 116, 52, 114, 51, 112, 48];
    true_username_rev.reverse();
    let true_username = from_utf8(&true_username_rev).unwrap();

    let result = match username {
        "" => String::from("Username is required."),
        username => {
            if username == true_username && password == get_true_password() {
                format!("Welcome back, {}.", username)
            }
            else {
                String::from("Operator not recognized. This incident will be reported.")
            }
        },
    };

    result    
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![check])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
