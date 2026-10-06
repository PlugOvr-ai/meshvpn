//! The desktop protocol between the browser and the session (carried over SSH and a local
//! WebSocket). Every message: type (u8), payload length (u32 LE), payload. Integers are LE.

// session -> browser
pub const S_INIT: u8 = 1; // w u16, h u16
pub const S_TILE: u8 = 2; // x u16, y u16, w u16, h u16, format u8 (1 png, 2 jpeg), image
pub const S_FRAME_END: u8 = 3; // the browser answers C_ACK once it has drawn the frame
pub const S_WINDOWS: u8 = 4; // JSON [{id, title, active}]
pub const S_CLIPBOARD: u8 = 5; // UTF-8 text copied in the session
pub const S_CURSOR: u8 = 6; // xhot u16, yhot u16, PNG
pub const S_APPS: u8 = 7; // JSON [{name, exec}]
pub const S_NOTICE: u8 = 8; // UTF-8 text to show
pub const S_FILES: u8 = 9; // JSON {path, parent, entries: [{name, dir, size, mtime, link}], error}
pub const S_FILE_DATA: u8 = 10; // id u32, offset u64, total u64, bytes (a file being read)
pub const S_FILE_DONE: u8 = 11; // JSON {id, ok, error}: end of a read error, upload or file operation

// browser -> session
pub const C_POINTER: u8 = 101; // x u16, y u16, buttons u8 (1 left, 2 right, 4 middle)
pub const C_WHEEL: u8 = 102; // dx i8, dy i8 (steps)
pub const C_KEY: u8 = 103; // down u8, char u8 (1: a typed character), keysym u32
pub const C_CLIPBOARD: u8 = 104; // UTF-8 text
pub const C_ACTIVATE: u8 = 105; // window u32
pub const C_CLOSE: u8 = 106; // window u32
pub const C_LAUNCH: u8 = 107; // UTF-8 command line
pub const C_ACK: u8 = 108;
pub const C_REFRESH: u8 = 109;
pub const C_RESIZE: u8 = 110; // w u16, h u16
pub const C_FILES: u8 = 111; // UTF-8 directory (empty: home)
pub const C_FILE_READ: u8 = 112; // id u32, UTF-8 path
pub const C_FILE_WRITE: u8 = 113; // id u32, offset u64, total u64, path length u16, path, bytes
pub const C_FILE_OP: u8 = 114; // JSON {id, op: mkdir|delete|rename, path, to}
pub const C_STOP: u8 = 120; // end the session (closes all apps)

pub const MAX_MESSAGE: usize = 32 << 20;

pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(5 + payload.len());
    f.push(kind);
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

/// Splits complete messages off the front of `buf`.
pub fn split(buf: &mut Vec<u8>) -> std::io::Result<Vec<Vec<u8>>> {
    let mut out = vec![];
    loop {
        if buf.len() < 5 {
            return Ok(out);
        }
        let len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if len > MAX_MESSAGE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        if buf.len() < 5 + len {
            return Ok(out);
        }
        out.push(buf.drain(..5 + len).collect());
    }
}

pub fn u16_at(p: &[u8], i: usize) -> u16 {
    p.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0)
}

pub fn u32_at(p: &[u8], i: usize) -> u32 {
    p.get(i..i + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_roundtrip() {
        let mut buf = frame(S_NOTICE, b"hello");
        buf.extend(frame(C_ACK, b""));
        buf.extend(&frame(S_INIT, &[1, 2, 3, 4])[..3]); // incomplete
        let msgs = split(&mut buf).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(&msgs[0][5..], b"hello");
        assert_eq!(msgs[1], vec![C_ACK, 0, 0, 0, 0]);
        assert_eq!(buf.len(), 3);
    }
}
