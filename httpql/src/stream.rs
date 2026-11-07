use serde::de::{DeserializeOwned, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::io::{self, Read};
use std::marker::PhantomData;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Stream a top-level JSON array one element at a time.
///
/// The input is never loaded into memory. Returning `ControlFlow::Break` from
/// the callback stops reading the file immediately.
pub fn stream_json_array<T, F>(reader: impl Read, on_item: F) -> Result<(), serde_json::Error>
where
    T: DeserializeOwned,
    F: FnMut(T) -> ControlFlow<()>,
{
    struct ArrayVisitor<T, F> {
        on_item: F,
        stop: Arc<AtomicBool>,
        _marker: PhantomData<T>,
    }

    impl<'de, T, F> Visitor<'de> for ArrayVisitor<T, F>
    where
        T: Deserialize<'de>,
        F: FnMut(T) -> ControlFlow<()>,
    {
        type Value = ();

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JSON array of request records")
        }

        fn visit_seq<A>(mut self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            while let Some(item) = seq.next_element::<T>()? {
                if let ControlFlow::Break(()) = (self.on_item)(item) {
                    self.stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
            Ok(())
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let reader = StoppableReader {
        inner: reader,
        stop: stop.clone(),
    };
    let mut deserializer = serde_json::Deserializer::from_reader(reader);

    let result = deserializer.deserialize_seq(ArrayVisitor {
        on_item,
        stop: stop.clone(),
        _marker: PhantomData,
    });

    // Once the callback asks to stop, the reader reports EOF. Ignore any
    // error that results from cutting the array short.
    if stop.load(Ordering::Relaxed) {
        Ok(())
    } else {
        result
    }
}

/// A reader that reports EOF as soon as the callback asks to stop.
struct StoppableReader<R> {
    inner: R,
    stop: Arc<AtomicBool>,
}

impl<R: Read> Read for StoppableReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.stop.load(Ordering::Relaxed) {
            return Ok(0);
        }
        self.inner.read(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Request;

    #[test]
    fn streams_each_array_element() {
        let json = r#"[
            {"id": 1, "host": "a", "method": "GET", "path": "/a"},
            {"id": 2, "host": "b", "method": "POST", "path": "/b"}
        ]"#;

        let mut ids = Vec::new();
        stream_json_array::<Request, _>(json.as_bytes(), |request| {
            ids.push(request.id);
            ControlFlow::Continue(())
        })
        .unwrap();

        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn stops_early_on_break() {
        let json = r#"[
            {"id": 1, "host": "a", "method": "GET", "path": "/a"},
            {"id": 2, "host": "b", "method": "POST", "path": "/b"}
        ]"#;

        let mut ids = Vec::new();
        stream_json_array::<Request, _>(json.as_bytes(), |request| {
            ids.push(request.id);
            ControlFlow::Break(())
        })
        .unwrap();

        assert_eq!(ids, vec![1]);
    }

    #[test]
    fn stops_early_on_break_with_buffered_reader() {
        let json = r#"[
            {"id": 1, "host": "a", "method": "GET", "path": "/a"},
            {"id": 2, "host": "b", "method": "POST", "path": "/b"},
            {"id": 3, "host": "c", "method": "GET", "path": "/c"}
        ]"#;

        let reader = std::io::BufReader::new(json.as_bytes());
        let mut ids = Vec::new();
        stream_json_array::<Request, _>(reader, |request| {
            ids.push(request.id);
            ControlFlow::Break(())
        })
        .unwrap();

        assert_eq!(ids, vec![1]);
    }
}
