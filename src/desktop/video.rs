//! The screen as an H.264 stream for browsers that can decode it (WebCodecs), encoded by the
//! GPU: NVENC (NVIDIA) or VA-API (Intel, AMD), through the system's ffmpeg. Far less data and
//! CPU than picture tiles at high resolutions and with moving content; without a hardware
//! encoder the session keeps sending tiles.
//!
//! ffmpeg reads the raw frames (BGRX, as the X server has them) on stdin and writes FLV on
//! stdout: every tag is one whole frame with its length, and the first one the decoder's setup
//! (avcC), which is just what the browser's VideoDecoder takes.

use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use tracing::{info, warn};

/// S_VIDEO payload kinds.
pub const CONFIG: u8 = 0;
pub const KEY: u8 = 1;
pub const DELTA: u8 = 2;

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Nvenc,
    Vaapi(String),
    /// On the CPU: only when asked for (MESHVPN_DESKTOP_ENCODER=libx264).
    X264,
}

impl Kind {
    pub fn name(&self) -> String {
        match self {
            Kind::Nvenc => "NVENC".into(),
            Kind::Vaapi(d) => format!("VA-API ({d})"),
            Kind::X264 => "x264 (CPU)".into(),
        }
    }

    fn args(&self, w: u16, h: u16) -> Vec<String> {
        let rate = format!("{}k", (w as u64 * h as u64 * 3 / 1000).clamp(2_000, 25_000));
        let mut a: Vec<String> = vec![];
        if let Kind::Vaapi(dev) = self {
            a.extend(["-vaapi_device".into(), dev.clone()]);
        }
        a.extend(
            [
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "rawvideo",
                "-pix_fmt",
                "bgr0",
                "-s",
                &format!("{w}x{h}"),
                "-r",
                "30",
                "-i",
                "-",
            ]
            .map(String::from),
        );
        let enc: &[&str] = match self {
            Kind::Nvenc => &[
                "-c:v",
                "h264_nvenc",
                "-preset",
                "p1",
                "-tune",
                "ull",
                "-zerolatency",
                "1",
                "-delay",
                "0",
                "-rc",
                "cbr",
                "-profile:v",
                "high",
            ],
            Kind::Vaapi(_) => &[
                "-vf",
                "format=nv12,hwupload",
                "-c:v",
                "h264_vaapi",
                "-profile:v",
                "high",
            ],
            Kind::X264 => &[
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
                "-pix_fmt",
                "yuv420p",
            ],
        };
        a.extend(enc.iter().map(|s| s.to_string()));
        a.extend(
            [
                "-bf",
                "0",
                "-g",
                "600",
                "-b:v",
                &rate,
                "-f",
                "flv",
                "-flush_packets",
                "1",
                "-",
            ]
            .map(String::from),
        );
        a
    }
}

/// The hardware encoder this machine's ffmpeg can use, if any (MESHVPN_DESKTOP_ENCODER=off,
/// nvenc, vaapi or libx264 decides instead). Takes a second: ffmpeg tries each.
pub fn pick() -> Option<Kind> {
    let want = std::env::var("MESHVPN_DESKTOP_ENCODER").unwrap_or_default();
    if want == "off" {
        return None;
    }
    let vaapi = || {
        std::fs::read_dir("/dev/dri")
            .ok()?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("renderD"))
            })
            .min()
            .map(|p| Kind::Vaapi(p.display().to_string()))
    };
    let candidates: Vec<Kind> = match want.as_str() {
        "nvenc" => vec![Kind::Nvenc],
        "vaapi" => vaapi().into_iter().collect(),
        "libx264" => vec![Kind::X264],
        _ => [Some(Kind::Nvenc), vaapi()].into_iter().flatten().collect(),
    };
    candidates.into_iter().find(works)
}

/// Encodes a few frames, so a listed encoder without its driver or device doesn't count.
fn works(kind: &Kind) -> bool {
    let (w, h) = (256u16, 144u16);
    let Ok(mut c) = Command::new("ffmpeg")
        .args(kind.args(w, h))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let frame = vec![0x40u8; w as usize * h as usize * 4];
    if let Some(mut i) = c.stdin.take() {
        for _ in 0..3 {
            let _ = i.write_all(&frame);
        }
    }
    let mut out = vec![];
    let _ = c.stdout.take().map(|mut o| o.read_to_end(&mut out));
    let ok = c.wait().map(|s| s.success()).unwrap_or(false);
    ok && out.starts_with(b"FLV")
}

/// One running encoder at one size.
pub struct Encoder {
    child: Child,
    frames: Option<mpsc::SyncSender<Vec<u8>>>,
    /// S_VIDEO payloads: kind, w u16, h u16, data.
    pub out: mpsc::Receiver<Vec<u8>>,
    pub w: u16,
    pub h: u16,
}

impl Encoder {
    pub fn start(kind: &Kind, w: u16, h: u16) -> Result<Self> {
        if !w.is_multiple_of(2) || !h.is_multiple_of(2) {
            bail!("H.264 needs an even size, not {w}x{h}");
        }
        let mut child = Command::new("ffmpeg")
            .args(kind.args(w, h))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("starting ffmpeg")?;
        let mut stdin = child.stdin.take().context("ffmpeg's stdin")?;
        let mut stdout = child.stdout.take().context("ffmpeg's stdout")?;
        // Frames go in through a thread: a busy encoder skips a frame instead of holding up
        // the session.
        let (ftx, frx) = mpsc::sync_channel::<Vec<u8>>(1);
        std::thread::spawn(move || {
            while let Ok(f) = frx.recv() {
                if stdin.write_all(&f).is_err() {
                    break;
                }
            }
        });
        let (otx, orx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            if let Err(e) = read_flv(&mut stdout, w, h, &otx) {
                warn!("video stream: {e:#}");
            }
        });
        info!("video: {} at {w}x{h}", kind.name());
        Ok(Encoder {
            child,
            frames: Some(ftx),
            out: orx,
            w,
            h,
        })
    }

    /// A frame for the encoder; false if it's still busy with the last one (this one is left).
    pub fn frame(&self, data: &[u8]) -> bool {
        match &self.frames {
            Some(tx) => tx.try_send(data.to_vec()).is_ok(),
            None => false,
        }
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        self.frames = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// FLV tags -> S_VIDEO payloads.
fn read_flv(r: &mut impl Read, w: u16, h: u16, tx: &mpsc::Sender<Vec<u8>>) -> Result<()> {
    let mut head = [0u8; 13];
    r.read_exact(&mut head)?;
    if &head[..3] != b"FLV" {
        bail!("not FLV");
    }
    loop {
        let mut th = [0u8; 11];
        if r.read_exact(&mut th).is_err() {
            return Ok(());
        }
        let size = u32::from_be_bytes([0, th[1], th[2], th[3]]) as usize;
        let mut data = vec![0u8; size];
        r.read_exact(&mut data)?;
        let mut prev = [0u8; 4];
        r.read_exact(&mut prev)?;
        // Video tags only: frame type/codec, AVC packet type, composition time, payload.
        if th[0] != 9 || data.len() < 5 || data[0] & 0x0f != 7 {
            continue;
        }
        let kind = match (data[1], data[0] >> 4) {
            (0, _) => CONFIG,
            (1, 1) => KEY,
            (1, _) => DELTA,
            _ => continue,
        };
        let mut p = Vec::with_capacity(5 + data.len() - 5);
        p.push(kind);
        p.extend_from_slice(&w.to_le_bytes());
        p.extend_from_slice(&h.to_le_bytes());
        p.extend_from_slice(&data[5..]);
        if tx.send(p).is_err() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flv_tags_become_frames() {
        let mut s = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
        let mut tag = |t: u8, body: &[u8]| {
            let n = body.len() as u32;
            s.extend_from_slice(&[t, (n >> 16) as u8, (n >> 8) as u8, n as u8, 0, 0, 0, 0, 0, 0, 0]);
            s.extend_from_slice(body);
            s.extend_from_slice(&(n + 11).to_be_bytes());
        };
        tag(18, b"metadata");
        tag(9, &[0x17, 0, 0, 0, 0, 1, 0x64, 0, 0x33]); // config
        tag(9, &[0x17, 1, 0, 0, 0, 0xaa]); // key
        tag(9, &[0x27, 1, 0, 0, 0, 0xbb]); // delta
        let (tx, rx) = mpsc::channel();
        read_flv(&mut &s[..], 640, 480, &tx).unwrap();
        let got: Vec<Vec<u8>> = rx.try_iter().collect();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0][0], CONFIG);
        assert_eq!(&got[0][5..], &[1, 0x64, 0, 0x33]);
        assert_eq!(got[1][0], KEY);
        assert_eq!(&got[1][1..5], &[128, 2, 224, 1]);
        assert_eq!(&got[2][..], &[DELTA, 128, 2, 224, 1, 0xbb]);
    }
}
