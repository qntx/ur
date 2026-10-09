#![no_main]

use bcur::ur::Decoder;
use bcur::{Received, State};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let mut decoder = Decoder::default();
    match decoder.receive(&s) {
        Err(e) if e.is_fatal() => {
            assert!(
                matches!(decoder.state(), State::Failed(_)),
                "fatal receive must fail the session"
            );
            assert_eq!(
                decoder.receive(&s).unwrap(),
                Received::Duplicate,
                "a failed session duplicates every later frame"
            );
            assert!(decoder.into_decoded().is_err());
        }
        Err(e) => {
            assert!(
                matches!(decoder.state(), State::Empty | State::Collecting(_)),
                "nonfatal receive must not fail the session: {e:?}"
            );
        }
        Ok(_) => match decoder.state() {
            State::Complete(_) => {
                assert!(decoder.into_decoded().is_ok());
            }
            State::Collecting(progress) => {
                assert!(progress.rank() < progress.fragment_count());
            }
            State::Empty | State::Failed(_) => {}
        },
    }
});
