use std::io::{self, BufRead, Write};

/// Read a password from the user, supporting both TTY and piped input
pub fn read_password(prompt: &str) -> Result<String, io::Error> {
    // Check if stdin is a TTY
    if atty::is(atty::Stream::Stdin) {
        // If we're in a TTY, use rpassword for secure password input
        rpassword::prompt_password(prompt)
    } else {
        // If stdin is piped, read from stdin directly
        print!("{}", prompt);
        io::stdout().flush()?;
        
        let stdin = io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        
        // Remove trailing newline
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        
        Ok(line)
    }
}

/// Read a password with confirmation
pub fn read_password_with_confirmation(
    prompt: &str,
    confirm_prompt: &str,
) -> Result<String, String> {
    let password = read_password(prompt)
        .map_err(|e| format!("Failed to read password: {}", e))?;
    
    let confirm = read_password(confirm_prompt)
        .map_err(|e| format!("Failed to read confirmation: {}", e))?;
    
    if password != confirm {
        return Err("Passwords do not match".to_string());
    }
    
    Ok(password)
} 