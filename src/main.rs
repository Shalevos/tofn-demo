mod common;
mod execute;
mod single_thread;

use single_thread::{basic_correctness as single_thread_basic_correctness};

fn main() {
    single_thread_basic_correctness();
}
