// Include the main.rs file directly since we can't use a binary crate as a library
// This makes all public items from main.rs available in the lib crate
include!("main.rs");
