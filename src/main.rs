mod common;
mod execute;
mod single_thread;
mod party;
mod multi_thread;

use single_thread::{basic_correctness as single_thread_basic_correctness};
use multi_thread::{basic_correctness as multi_thread_basic_correctness};

fn main() {
    // single_thread_basic_correctness();
    multi_thread_basic_correctness();
}
