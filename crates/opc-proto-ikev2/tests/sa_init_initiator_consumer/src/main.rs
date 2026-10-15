#[path = "../../sa_init_initiator/composition.rs"]
mod composition;

fn main() {
    composition::run();
    println!("Non-testkit initiator composition matches the independent vector.");
}
