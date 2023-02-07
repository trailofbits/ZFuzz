use crate::{
    arg_setup::DEBUG_PRINT,
    Statistics,
    targets::targets::TARGETS,
};

use std::time::Duration;
use core::fmt;

use console::Term;
use rustc_hash::FxHashMap;
use num_format::{Locale, ToFormattedString};

/// Different log-types that can be used to print out messages in different colors
pub enum LogType {
    Neutral = 0,
    Success = 1,
    Failure = 2,
}

/// Color a string green
pub struct Green(pub String);
impl fmt::Display for Green {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { 
        write!(f, "\x1B[32m")?;
        write!(f, "{}", self.0)?;
        write!(f, "\x1B[0m")?;
        Ok(())
    }
}

/// Color a string blue
pub struct Blue(pub String);
impl fmt::Display for Blue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { 
        write!(f, "\x1B[34m")?;
        write!(f, "{}", self.0)?;
        write!(f, "\x1B[0m")?;
        Ok(())
    }
}

/// Color a string red
pub struct Red(pub String);
impl fmt::Display for Red {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { 
        write!(f, "\x1B[31m")?;
        write!(f, "{}", self.0)?;
        write!(f, "\x1B[0m")?;
        Ok(())
    }
}

/// Small wrapper to print out colored log messages
pub fn log(color: LogType, msg: &str) {
    if *DEBUG_PRINT.get().unwrap() {
        match color {
            LogType::Neutral => {
                println!("{} {}", Blue("[-]".to_string()), msg);
            },
            LogType::Success => {
                println!("{} {}", Green("[+]".to_string()), msg);
            },
            LogType::Failure => {
                println!("{} {}", Red("[!]".to_string()), msg);
            },
        }
    }
}

/// Print out statistics in a nicely formated static screen
pub fn print_stats(term: &Term, stats: &FxHashMap<usize, Statistics>, elapsed_time: f64, 
                   last_cov: f64) {
    term.clear_screen().unwrap();
    term.move_cursor_to(0, 2).unwrap();

    // Print out error message instead of standard output if the terminal size is too small to
    // properly display output
    let (x, y) = term.size();
    if x < 25 || y < 50 {
        term.write_line(&format!("Increase terminal size to 25:50 (Cur: {}:{})", x, y)).unwrap();
        term.flush().unwrap();
        return;
    }

    term.write_line(
        &format!("{}", Green("\t\t[ ZFUZZ ]\n".to_string()))
    ).unwrap();

    let duration    = Duration::from_secs_f64(elapsed_time);
    let elapsed_sec = duration.as_secs() % 60;
    let elapsed_min = (duration.as_secs() / 60) % 60;
    let elapsed_hr  = (duration.as_secs() / 60) / 60;

    term.write_line(
        &format!("Run time: {:02}:{:02}:{:02}", elapsed_hr, elapsed_min, elapsed_sec)).unwrap();
        term.move_cursor_down(2).unwrap();

    for (_, cur_stats) in stats {
        term.write_line(&format!("{}", Blue(format!("Target-{}", cur_stats.target_id).to_string())))
            .unwrap();
        term.move_cursor_down(1).unwrap();
        term.write_line(&format!("\t\t+----Dynamic Stats ----+")).unwrap();
        term.write_line(&format!("   Unique Crashes: {}", 
                                 cur_stats.ucrashes.to_formatted_string(&Locale::en))).unwrap();
        term.write_line(&format!("   Crashes: {}", 
                                 cur_stats.crashes.to_formatted_string(&Locale::en))).unwrap();

        term.move_cursor_up(2).unwrap();
        term.move_cursor_right(30).unwrap();
        term.write_line(
            &format!("Total Fuzz Cases: {:12}",
            cur_stats.total_cases.to_formatted_string(&Locale::en), 
            )).unwrap();

        term.move_cursor_right(30).unwrap();
        term.write_line(
            &format!("Fuzz Cases/Sec: {:12}",
            (cur_stats.total_cases / elapsed_time as usize).to_formatted_string(&Locale::en), 
            )).unwrap();

        let duration  = Duration::from_secs_f64(elapsed_time - last_cov);
        let cov_sec   = duration.as_secs() % 60;
        let cov_min   = (duration.as_secs() / 60) % 60;
        let cov_hr    = (duration.as_secs() / 60) / 60;

        term.write_line(&format!("   Coverage: {}", cur_stats.coverage)).unwrap();

        term.move_cursor_up(1).unwrap();
        term.move_cursor_right(27).unwrap();
        term.write_line(&format!("   Time since last cov: {:02}:{:02}:{:02}", 
                        cov_hr, cov_min, cov_sec)).unwrap();

        term.write_line(&format!("   Corpus-Size: {}", cur_stats.num_inputs)).unwrap();

        if cur_stats.total_cases != 0 {
            term.write_line(&format!("   Invalid Instrs: {:.2}", 
                (cur_stats.invalid_insns as f64 / cur_stats.total_cases as f64))).unwrap();
            term.move_cursor_right(26).unwrap();
            term.move_cursor_up(1).unwrap();
            term.write_line(&format!("-  (0.00-1.00, 1.00 is bad)")).unwrap();   
        }

        let mut cur_target_index = std::usize::MAX;
        TARGETS.iter().enumerate().for_each(|(i, t)| if t.target_id == cur_stats.target_id {
            cur_target_index = i;
        });

        term.move_cursor_down(1).unwrap();
        term.write_line(&format!("\t\t+----Static Settings ----+")).unwrap();
        term.write_line(&format!("   Num Threads: {}", 
                                 TARGETS[cur_target_index].num_threads)).unwrap();
        term.move_cursor_right(27).unwrap();
        term.move_cursor_up(1).unwrap();
        term.write_line(&format!("   Instr Timeout set: {}", 
                                 TARGETS[cur_target_index].instr_timeout)).unwrap();
        term.write_line(&format!("   Time Timeout set: {}", 
                                 TARGETS[cur_target_index].time_timeout)).unwrap();

        term.move_cursor_down(2).unwrap();

        // Flush buffer and write to terminal
        term.flush().unwrap();
    }
}
