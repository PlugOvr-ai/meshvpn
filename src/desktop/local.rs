//! `meshvpn desktop local`: the user's desktop session on this machine's own screen. Started by
//! the login entry ("meshvpn desktop" in the login screen, `meshvpn desktop setup --login`): the
//! desktop runs in its own X server and keeps running when the person leaves the desk; the
//! monitor only shows it, like a browser does from elsewhere - at the same time, too.
//!
//! A fullscreen window on the screen's X server; the picture comes from the session as raw
//! pixels, keys go there as the keyboard's own key codes (its layout is copied over first).

use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tracing::warn;
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::render::{self, ConnectionExt as _};
use x11rb::protocol::xproto::*;
use x11rb::rust_connection::RustConnection;

use super::proto::*;

/// Leave the desk, keep the session: Ctrl+Alt+End.
const LEAVE_KEYSYM: u32 = 0xff57;

struct Screen {
    conn: RustConnection,
    win: Window,
    pixmap: Pixmap,
    gc: Gcontext,
    w: u16,
    h: u16,
    depth: u8,
}

impl Screen {
    fn tile(&self, x: u16, y: u16, w: u16, h: u16, data: &[u8]) {
        if x >= self.w || y >= self.h || data.len() < w as usize * h as usize * 4 {
            return;
        }
        let _ = self.conn.put_image(
            ImageFormat::Z_PIXMAP,
            self.pixmap,
            self.gc,
            w,
            h,
            x as i16,
            y as i16,
            0,
            self.depth,
            data,
        );
        let _ = self.conn.copy_area(
            self.pixmap,
            self.win,
            self.gc,
            x as i16,
            y as i16,
            x as i16,
            y as i16,
            w,
            h,
        );
    }

    fn expose(&self, x: u16, y: u16, w: u16, h: u16) {
        let _ = self.conn.copy_area(
            self.pixmap,
            self.win,
            self.gc,
            x as i16,
            y as i16,
            x as i16,
            y as i16,
            w,
            h,
        );
        let _ = self.conn.flush();
    }

    /// The session's cursor (PNG, RGBA) as this window's cursor.
    fn cursor(&self, xhot: u16, yhot: u16, png_data: &[u8]) -> Result<()> {
        let dec = png::Decoder::new(std::io::Cursor::new(png_data));
        let mut r = dec.read_info()?;
        let mut buf = vec![0; r.output_buffer_size().unwrap_or(0)];
        let info = r.next_frame(&mut buf)?;
        if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
            bail!("cursor: unexpected PNG format");
        }
        let (w, h) = (info.width as u16, info.height as u16);
        // Premultiplied BGRA, as Render wants it.
        let mut px = Vec::with_capacity(w as usize * h as usize * 4);
        for c in buf[..info.buffer_size()].as_chunks::<4>().0 {
            let a = c[3] as u32;
            let m = |v: u8| ((v as u32 * a + 127) / 255) as u8;
            px.extend_from_slice(&[m(c[2]), m(c[1]), m(c[0]), c[3]]);
        }
        let formats = self.conn.render_query_pict_formats()?.reply()?;
        let fmt = formats
            .formats
            .iter()
            .find(|f| {
                f.depth == 32
                    && f.type_ == render::PictType::DIRECT
                    && f.direct.alpha_mask == 0xff
                    && f.direct.alpha_shift == 24
                    && f.direct.red_shift == 16
            })
            .ok_or_else(|| anyhow!("no ARGB32 picture format"))?
            .id;
        let pm = self.conn.generate_id()?;
        self.conn.create_pixmap(32, pm, self.win, w, h)?;
        let gc = self.conn.generate_id()?;
        self.conn.create_gc(gc, pm, &CreateGCAux::new())?;
        self.conn
            .put_image(ImageFormat::Z_PIXMAP, pm, gc, w, h, 0, 0, 0, 32, &px)?;
        let pic = self.conn.generate_id()?;
        self.conn
            .render_create_picture(pic, pm, fmt, &render::CreatePictureAux::new())?;
        let cur = self.conn.generate_id()?;
        self.conn.render_create_cursor(cur, pic, xhot, yhot)?;
        self.conn
            .change_window_attributes(self.win, &ChangeWindowAttributesAux::new().cursor(cur))?;
        self.conn.free_cursor(cur)?;
        self.conn.render_free_picture(pic)?;
        self.conn.free_gc(gc)?;
        self.conn.free_pixmap(pm)?;
        self.conn.flush()?;
        Ok(())
    }
}

pub fn run() -> Result<()> {
    arrange_monitors();
    let (conn, num) = RustConnection::connect(None).context("connecting to this machine's screen ($DISPLAY)")?;
    let root_info = conn.setup().roots[num].clone();
    let (root, w, h, depth) = (
        root_info.root,
        root_info.width_in_pixels,
        root_info.height_in_pixels,
        root_info.root_depth,
    );
    let bpp = conn
        .setup()
        .pixmap_formats
        .iter()
        .find(|f| f.depth == depth)
        .map(|f| f.bits_per_pixel);
    if depth != 24 || bpp != Some(32) || conn.setup().image_byte_order != ImageOrder::LSB_FIRST {
        bail!("this screen's pixel format (depth {depth}, {bpp:?} bits) isn't supported");
    }

    // The desktop: running, or started now (Xfce if installed).
    let stream = super::session::connect("auto", &|t| eprintln!("meshvpn desktop: {t}"))?;
    if let Err(e) = copy_keymap() {
        warn!("copying the keyboard layout: {e:#}");
    }

    let win = conn.generate_id()?;
    conn.create_window(
        x11rb::COPY_DEPTH_FROM_PARENT,
        win,
        root,
        0,
        0,
        w,
        h,
        0,
        WindowClass::INPUT_OUTPUT,
        x11rb::COPY_FROM_PARENT,
        &CreateWindowAux::new()
            .background_pixel(root_info.black_pixel)
            .override_redirect(1)
            .event_mask(
                EventMask::KEY_PRESS
                    | EventMask::KEY_RELEASE
                    | EventMask::BUTTON_PRESS
                    | EventMask::BUTTON_RELEASE
                    | EventMask::POINTER_MOTION
                    | EventMask::EXPOSURE,
            ),
    )?;
    let pixmap = conn.generate_id()?;
    conn.create_pixmap(depth, pixmap, win, w, h)?;
    let gc = conn.generate_id()?;
    conn.create_gc(
        gc,
        pixmap,
        &CreateGCAux::new()
            .foreground(root_info.black_pixel)
            .graphics_exposures(0),
    )?;
    conn.poly_fill_rectangle(
        pixmap,
        gc,
        &[Rectangle {
            x: 0,
            y: 0,
            width: w,
            height: h,
        }],
    )?;
    conn.map_window(win)?;
    conn.flush()?;
    // The keyboard to this window (nothing else runs on this screen).
    for _ in 0..50 {
        let g = conn
            .grab_keyboard(true, win, x11rb::CURRENT_TIME, GrabMode::ASYNC, GrabMode::ASYNC)?
            .reply()?;
        if g.status == GrabStatus::SUCCESS {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    conn.set_input_focus(InputFocus::POINTER_ROOT, win, x11rb::CURRENT_TIME)?;
    let leave = keycode_of(&conn, LEAVE_KEYSYM);

    let screen = Arc::new(Screen {
        conn,
        win,
        pixmap,
        gc,
        w,
        h,
        depth,
    });
    let out = Arc::new(Mutex::new(stream.try_clone()?));
    let send = {
        let out = out.clone();
        move |kind: u8, p: &[u8]| {
            let _ = out.lock().unwrap().write_all(&frame(kind, p));
        }
    };
    // The screen's size, then its monitors (they must fit the screen).
    send(C_RESIZE, &[w.to_le_bytes(), h.to_le_bytes()].concat());
    let monitors = monitors_of(&screen.conn, root);
    send(
        C_LOCAL,
        serde_json::json!({ "monitors": monitors }).to_string().as_bytes(),
    );

    // The picture.
    {
        let screen = screen.clone();
        let send = send.clone();
        let mut stream = stream;
        std::thread::spawn(move || {
            let mut buf = vec![];
            let mut chunk = vec![0u8; 1 << 20];
            loop {
                let n = match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                let Ok(msgs) = split(&mut buf) else { break };
                for m in msgs {
                    let (kind, p) = (m[0], &m[5..]);
                    match kind {
                        S_TILE if p.get(8) == Some(&TILE_RAW) => {
                            screen.tile(u16_at(p, 0), u16_at(p, 2), u16_at(p, 4), u16_at(p, 6), &p[9..])
                        }
                        S_FRAME_END => {
                            let _ = screen.conn.flush();
                            send(C_ACK, b"");
                        }
                        S_CURSOR => {
                            if let Err(e) = screen.cursor(u16_at(p, 0), u16_at(p, 2), &p[4..]) {
                                warn!("cursor: {e:#}");
                            }
                        }
                        S_NOTICE => eprintln!("meshvpn desktop: {}", String::from_utf8_lossy(p)),
                        _ => {}
                    }
                }
            }
            // The session ended (logged out of it): so does this login.
            std::process::exit(0);
        });
    }

    // Keyboard and mouse.
    let mut pressed: HashSet<u8> = HashSet::new();
    let mut buttons = 0u8;
    loop {
        let ev = screen.conn.wait_for_event()?;
        match ev {
            Event::Expose(e) => screen.expose(e.x, e.y, e.width, e.height),
            Event::KeyPress(e) => {
                let mods = u16::from(e.state);
                let ctrl_alt = u16::from(KeyButMask::CONTROL | KeyButMask::MOD1);
                if Some(e.detail) == leave && mods & ctrl_alt == ctrl_alt {
                    // Leave the desk: the keys let go in the session, which keeps running.
                    for kc in pressed.drain() {
                        send(C_RAWKEY, &[0, kc]);
                    }
                    let _ = out.lock().unwrap().flush();
                    return Ok(());
                }
                pressed.insert(e.detail);
                send(C_RAWKEY, &[1, e.detail]);
            }
            Event::KeyRelease(e) => {
                pressed.remove(&e.detail);
                send(C_RAWKEY, &[0, e.detail]);
            }
            Event::MotionNotify(e) => pointer(&send, e.event_x, e.event_y, buttons),
            Event::ButtonPress(e) | Event::ButtonRelease(e) => {
                let down = matches!(ev, Event::ButtonPress(_));
                let bit = match e.detail {
                    1 => 1,
                    3 => 2,
                    2 => 4,
                    4..=7 => {
                        if down {
                            let (dx, dy): (i8, i8) = match e.detail {
                                4 => (0, -1),
                                5 => (0, 1),
                                6 => (-1, 0),
                                _ => (1, 0),
                            };
                            send(C_WHEEL, &[dx as u8, dy as u8]);
                        }
                        continue;
                    }
                    _ => continue,
                };
                if down {
                    buttons |= bit;
                } else {
                    buttons &= !bit;
                }
                pointer(&send, e.event_x, e.event_y, buttons);
            }
            _ => {}
        }
    }
}

/// The monitors of this screen, for the session to have the same (its panel on the primary
/// one, windows maximized to one monitor).
fn monitors_of(conn: &RustConnection, root: Window) -> Vec<serde_json::Value> {
    use x11rb::protocol::randr::ConnectionExt as _;
    let _ = conn.randr_query_version(1, 5).ok().and_then(|c| c.reply().ok());
    let Some(r) = conn.randr_get_monitors(root, true).ok().and_then(|c| c.reply().ok()) else {
        return vec![];
    };
    // One spanning others isn't a monitor of its own.
    let inside = |a: &x11rb::protocol::randr::MonitorInfo, b: &x11rb::protocol::randr::MonitorInfo| {
        a.x >= b.x
            && a.y >= b.y
            && a.x as i32 + a.width as i32 <= b.x as i32 + b.width as i32
            && a.y as i32 + a.height as i32 <= b.y as i32 + b.height as i32
    };
    r.monitors
        .iter()
        .filter(|b| {
            !r.monitors
                .iter()
                .any(|a| (a.width, a.height) != (b.width, b.height) && inside(a, b))
        })
        .map(|m| serde_json::json!({ "x": m.x, "y": m.y, "w": m.width, "h": m.height, "primary": m.primary }))
        .collect()
}

/// w, h, x, y
type Geo = (i32, i32, i32, i32);

/// A new X server (the login screen's for a second user) turns monitors on as it likes:
/// mirrored, or just one. Connected monitors that are off or overlap: side by side, each at its
/// preferred size, the primary first.
fn arrange_monitors() {
    let Ok(o) = std::process::Command::new("xrandr").arg("--current").output() else {
        return;
    };
    // NAME connected [primary] [WxH+X+Y] ...
    let mut outs: Vec<(String, bool, Option<Geo>)> = vec![];
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let mut it = line.split_whitespace();
        let (Some(name), Some("connected")) = (it.next(), it.next()) else {
            continue;
        };
        let rest: Vec<&str> = it.collect();
        let primary = rest.first() == Some(&"primary");
        let geo = rest.iter().find_map(|t| {
            let (wh, xy) = t.split_once('+')?;
            let (w, h) = wh.split_once('x')?;
            let (x, y) = xy.split_once('+')?;
            Some((w.parse().ok()?, h.parse().ok()?, x.parse().ok()?, y.parse().ok()?))
        });
        outs.push((name.to_string(), primary, geo));
    }
    if outs.len() < 2 {
        return;
    }
    let overlap = |a: Geo, b: Geo| a.2 < b.2 + b.0 && b.2 < a.2 + a.0 && a.3 < b.3 + b.1 && b.3 < a.3 + a.1;
    let on: Vec<_> = outs.iter().filter_map(|o| o.2).collect();
    let fine = on.len() == outs.len()
        && on
            .iter()
            .enumerate()
            .all(|(i, a)| on[i + 1..].iter().all(|b| !overlap(*a, *b)));
    if fine {
        return;
    }
    outs.sort_by_key(|o| !o.1);
    let mut args: Vec<String> = vec![];
    for (i, (name, _, _)) in outs.iter().enumerate() {
        args.extend(["--output".into(), name.clone(), "--auto".into()]);
        if i == 0 {
            args.extend(["--primary".into(), "--pos".into(), "0x0".into()]);
        } else {
            args.extend(["--right-of".into(), outs[i - 1].0.clone()]);
        }
    }
    match std::process::Command::new("xrandr").args(&args).status() {
        Ok(s) if s.success() => eprintln!("meshvpn desktop: monitors side by side: xrandr {}", args.join(" ")),
        _ => eprintln!(
            "meshvpn desktop: arranging the monitors failed: xrandr {}",
            args.join(" ")
        ),
    }
}

fn pointer(send: &impl Fn(u8, &[u8]), x: i16, y: i16, buttons: u8) {
    let mut p = Vec::with_capacity(5);
    p.extend_from_slice(&(x.max(0) as u16).to_le_bytes());
    p.extend_from_slice(&(y.max(0) as u16).to_le_bytes());
    p.push(buttons);
    send(C_POINTER, &p);
}

fn keycode_of(conn: &RustConnection, keysym: u32) -> Option<u8> {
    let (min, max) = (conn.setup().min_keycode, conn.setup().max_keycode);
    let r = conn.get_keyboard_mapping(min, max - min + 1).ok()?.reply().ok()?;
    let per = r.keysyms_per_keycode as usize;
    r.keysyms
        .chunks(per.max(1))
        .position(|syms| syms.contains(&keysym))
        .map(|i| min + i as u8)
}

/// This screen's keyboard layout into the session's X server (`xkbcomp` there and back), so
/// key codes mean the same in both: AltGr, dead keys and all.
fn copy_keymap() -> Result<()> {
    let dir = super::session::runtime_dir()?;
    let display = std::fs::read_to_string(dir.join("display")).context("the session's display")?;
    let xkbcomp = super::bundle::find()
        .map(|b| b.bin_dir().join("xkbcomp"))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| "xkbcomp".into());
    let here = std::env::var("DISPLAY").unwrap_or_default();
    let file = dir.join("keymap.xkb");
    let ok = std::process::Command::new(&xkbcomp)
        .args(["-w", "0", "-xkb", &here])
        .arg(&file)
        .status()?
        .success();
    if !ok {
        bail!("reading the keyboard layout of {here}");
    }
    let ok = std::process::Command::new(&xkbcomp)
        .args(["-w", "0"])
        .arg(&file)
        .arg(display.trim())
        .env("XAUTHORITY", dir.join("Xauthority"))
        .status()?
        .success();
    if !ok {
        bail!("setting the keyboard layout of the session");
    }
    Ok(())
}
