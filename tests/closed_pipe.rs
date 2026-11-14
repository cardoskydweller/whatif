use std::process::Command;

#[test]
fn a_reader_that_closed_its_end_of_the_pipe_stops_whatif_quietly() {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = Command::new(env!("CARGO_BIN_EXE_whatif")).arg("--version").stdout(writer).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.is_empty(), "as `whatif … | head` would print: {err}");
}
