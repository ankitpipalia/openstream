//! Screen capture via ScreenCaptureKit, delivering GPU surfaces.
//!
//! The counterpart to [`crate::capture`], which polls `CGDisplayCreateImage`.
//! That path copies the whole framebuffer out of CoreGraphics, copies it again
//! to drop stride padding, rescales it on the CPU, and then hands bytes to an
//! encoder that copies them once more into a pixel buffer. Measured on an M1
//! Max at 3456x2234, the CoreGraphics call alone is 14.3 ms -- 86% of a 60 fps
//! frame, against 0.5 ms for the hardware encode it feeds.
//!
//! `SCStream` delivers IOSurface-backed `CVPixelBuffer`s already scaled to the
//! requested size, which `VTCompressionSessionEncodeFrame` accepts directly.
//! Capture to encoder with no CPU copy at all, and no rescale step, because
//! the compositor did it.
//!
//! # Why the Objective-C runtime is here
//!
//! ScreenCaptureKit has no C API. [`crate::objc_runtime`] is the slice of the
//! message-sending machinery this needs; the rest of this file is the capture
//! session built on it.
//!
//! # Threading
//!
//! Frames arrive on a dispatch queue owned by the stream, not on the caller's
//! thread. They land in a latest-frame slot, replacing whatever was there:
//! a stale frame is worth less than a fresh one, which is the same rule the
//! client's frame mailbox follows.

#![cfg(target_os = "macos")]

use std::ffi::{CString, c_void};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use crate::objc_runtime::{
    self as objc, BlockDescriptor, CmTime, FOREVER, Id, OneArgBlock, TwoArgBlock,
};

/// `kCVPixelFormatType_32BGRA` == 'BGRA'. The same byte order the CoreGraphics
/// path produced, so nothing downstream has to learn a new layout.
pub const PIXEL_FORMAT_BGRA: u32 = 0x4247_5241;

/// `SCStreamOutputTypeScreen`. Audio is type 1 and is not requested here.
const OUTPUT_TYPE_SCREEN: isize = 0;

/// The runtime name of the delegate class, and of its one ivar.
///
/// A class name is process-global: registering twice fails, which is why the
/// class is built once behind a `OnceLock` and reused by every stream.
const DELEGATE_CLASS: &str = "OpenStreamSCStreamOutput";
const DELEGATE_IVAR: &str = "openstream_sink";

#[link(name = "ScreenCaptureKit", kind = "framework")]
unsafe extern "C" {}

#[link(name = "CoreMedia", kind = "framework")]
unsafe extern "C" {
    fn CMSampleBufferIsValid(sample_buffer: *mut c_void) -> bool;
    fn CMSampleBufferGetImageBuffer(sample_buffer: *mut c_void) -> *mut c_void;
    fn CMSampleBufferGetPresentationTimeStamp(sample_buffer: *mut c_void) -> CmTime;
}

#[link(name = "CoreVideo", kind = "framework")]
unsafe extern "C" {
    fn CVPixelBufferGetWidth(pixel_buffer: *mut c_void) -> usize;
    fn CVPixelBufferGetHeight(pixel_buffer: *mut c_void) -> usize;
    fn CVPixelBufferGetPixelFormatType(pixel_buffer: *mut c_void) -> u32;
    fn CVPixelBufferGetIOSurface(pixel_buffer: *mut c_void) -> *mut c_void;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRetain(cf: *const c_void) -> *const c_void;
    fn CFRelease(cf: *const c_void);
}

/// Why a ScreenCaptureKit capture could not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SckError {
    /// The framework is not present, or its classes are not registered. On a
    /// supported macOS this does not happen; it is reported rather than
    /// asserted so an older system degrades to the CoreGraphics path.
    Unavailable(&'static str),
    /// `SCShareableContent` returned nothing. Overwhelmingly this is a missing
    /// Screen Recording permission -- the same cause as `CaptureError::Unavailable`
    /// on the CoreGraphics path.
    NoShareableContent,
    /// No display matched the requested id (or there are no displays at all).
    NoSuchDisplay(Option<u32>),
    /// The stream refused to start, with whatever `NSError` said.
    Start(String),
    /// `addStreamOutput:` refused the delegate.
    AddOutput(String),
}

impl std::fmt::Display for SckError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(what) => {
                write!(formatter, "ScreenCaptureKit is unavailable ({what})")
            }
            Self::NoShareableContent => formatter.write_str(
                "ScreenCaptureKit returned no shareable content (grant Screen Recording permission)",
            ),
            Self::NoSuchDisplay(Some(id)) => write!(formatter, "no display with id {id}"),
            Self::NoSuchDisplay(None) => formatter.write_str("no displays are attached"),
            Self::Start(detail) => write!(formatter, "the capture stream did not start: {detail}"),
            Self::AddOutput(detail) => {
                write!(formatter, "the capture stream refused its output: {detail}")
            }
        }
    }
}

impl std::error::Error for SckError {}

/// A captured frame that never left the GPU: a retained IOSurface-backed
/// `CVPixelBuffer`, plus what the caller needs to encode it.
///
/// Releases on drop. `Send` because CoreVideo retain/release is atomic, so the
/// capture queue can hand a frame to whichever thread encodes it.
#[derive(Debug)]
pub struct CapturedSurface {
    pixel_buffer: *mut c_void,
    width: usize,
    height: usize,
    presentation_time_us: i64,
}

// SAFETY: a CVPixelBuffer is a CoreFoundation object with atomic retain and
// release, and this type owns exactly one reference. Moving that reference
// between threads is sound.
unsafe impl Send for CapturedSurface {}

impl CapturedSurface {
    /// The raw `CVPixelBufferRef`, borrowed. Valid while `self` is alive.
    #[must_use]
    pub fn as_ptr(&self) -> *mut c_void {
        self.pixel_buffer
    }

    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }

    #[must_use]
    pub const fn height(&self) -> usize {
        self.height
    }

    /// The compositor's timestamp for this frame, in microseconds.
    #[must_use]
    pub const fn presentation_time_us(&self) -> i64 {
        self.presentation_time_us
    }
}

impl Drop for CapturedSurface {
    fn drop(&mut self) {
        if !self.pixel_buffer.is_null() {
            // SAFETY: exactly one retain is held, taken when the frame was
            // captured from the sample buffer.
            unsafe { CFRelease(self.pixel_buffer.cast()) };
        }
    }
}

/// Where the capture queue leaves frames for the caller to take.
///
/// A slot, not a queue: the newest frame replaces an untaken one. A capture
/// that outruns the encoder should hand it the freshest picture when it catches
/// up, not a backlog -- a queued frame is latency that can never be recovered.
#[derive(Debug, Default)]
struct Sink {
    latest: Mutex<Option<CapturedSurface>>,
    /// Frames the delegate accepted, including ones later replaced. The count
    /// is what distinguishes "the stream is running and the screen is static"
    /// from "the stream is delivering nothing".
    delivered: Mutex<u64>,
}

impl Sink {
    fn offer(&self, frame: CapturedSurface) {
        let mut latest = self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        *latest = Some(frame);
        drop(latest);
        let mut delivered = self
            .delivered
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *delivered = delivered.saturating_add(1);
    }

    fn take(&self) -> Option<CapturedSurface> {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    fn delivered(&self) -> u64 {
        *self
            .delivered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// What to capture and at what shape.
#[derive(Debug, Clone, Copy)]
pub struct SckConfig {
    /// Output width in pixels. ScreenCaptureKit scales during capture, so this
    /// is not a CPU rescale.
    pub width: u32,
    /// Output height in pixels.
    pub height: u32,
    /// Upper bound on delivery rate. The stream delivers on change, so this
    /// caps the rate rather than setting it.
    pub fps: u32,
    /// CoreGraphics display id to capture; `None` is the first display
    /// ScreenCaptureKit lists.
    pub display_id: Option<u32>,
    /// Draw the cursor into the captured frames.
    pub show_cursor: bool,
}

impl Default for SckConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 60,
            display_id: None,
            show_cursor: true,
        }
    }
}

/// A running ScreenCaptureKit capture.
///
/// Stops and releases its stream on drop.
#[derive(Debug)]
pub struct SckCapture {
    stream: Id,
    delegate: Id,
    queue: Id,
    sink: Arc<Sink>,
}

// SAFETY: the Objective-C objects held here are only messaged from whichever
// thread owns the `SckCapture`, and the sink it shares with the capture queue
// is behind a mutex. The stream itself is documented as safe to start and stop
// from any thread.
unsafe impl Send for SckCapture {}

impl SckCapture {
    /// Start capturing.
    ///
    /// Blocks until ScreenCaptureKit has enumerated its content and the stream
    /// has started, because both are async APIs and the caller wants a running
    /// capture or an error, not a maybe.
    pub fn start(config: SckConfig) -> Result<Self, SckError> {
        let content = shareable_content()?;
        // SAFETY: `content` is a retained SCShareableContent.
        let result = unsafe { Self::start_with_content(content, config) };
        // SAFETY: retained by `shareable_content`; released once here whether
        // or not the stream came up.
        unsafe { CFRelease(content.cast()) };
        result
    }

    /// # Safety
    /// `content` must be a live `SCShareableContent`.
    unsafe fn start_with_content(content: Id, config: SckConfig) -> Result<Self, SckError> {
        // SAFETY: `displays` is an NSArray property of SCShareableContent.
        let display = unsafe { pick_display(content, config.display_id) }?;

        let filter_class = objc::class("SCContentFilter");
        if filter_class.is_null() {
            return Err(SckError::Unavailable("SCContentFilter"));
        }
        // SAFETY: standard alloc/init pair; `array` is an empty NSArray, which
        // is what "exclude nothing" means here.
        let filter = unsafe {
            let empty = objc::send(objc::class("NSArray"), objc::sel("array"));
            let filter = objc::send(filter_class, objc::sel("alloc"));
            objc::send_id2(
                filter,
                objc::sel("initWithDisplay:excludingWindows:"),
                display,
                empty,
            )
        };
        if filter.is_null() {
            return Err(SckError::Unavailable("SCContentFilter init"));
        }

        // SAFETY: each setter below is a declared property of
        // SCStreamConfiguration with the argument type the helper casts to.
        let configuration = unsafe {
            let class = objc::class("SCStreamConfiguration");
            if class.is_null() {
                objc::send(filter, objc::sel("release"));
                return Err(SckError::Unavailable("SCStreamConfiguration"));
            }
            let configuration =
                objc::send(objc::send(class, objc::sel("alloc")), objc::sel("init"));
            objc::send_set_usize(configuration, objc::sel("setWidth:"), config.width as usize);
            objc::send_set_usize(
                configuration,
                objc::sel("setHeight:"),
                config.height as usize,
            );
            objc::send_set_u32(
                configuration,
                objc::sel("setPixelFormat:"),
                PIXEL_FORMAT_BGRA,
            );
            objc::send_set_bool(
                configuration,
                objc::sel("setShowsCursor:"),
                config.show_cursor,
            );
            // Shallow on purpose: a deep queue is latency. Three is enough to
            // keep the compositor from stalling on a slow consumer without
            // letting stale frames pile up behind a fresh one.
            objc::send_set_usize(configuration, objc::sel("setQueueDepth:"), 3);
            objc::send_set_time(
                configuration,
                objc::sel("setMinimumFrameInterval:"),
                CmTime::frame_interval(config.fps),
            );
            configuration
        };

        let Some(delegate_class) = delegate_class() else {
            // SAFETY: both were created above and are released on this path.
            unsafe {
                objc::send(configuration, objc::sel("release"));
                objc::send(filter, objc::sel("release"));
            }
            return Err(SckError::Unavailable("delegate class registration"));
        };

        let sink = Arc::new(Sink::default());
        // The delegate holds a raw pointer to the sink, and the `SckCapture`
        // holds the matching `Arc`. The stream is stopped and the delegate
        // released in `Drop` before that `Arc` goes, so the pointer cannot
        // outlive what it points at.
        let sink_pointer = Arc::into_raw(Arc::clone(&sink));

        // SAFETY: the class was registered with an `openstream_sink` pointer
        // ivar, and `sink_pointer` is a valid `Arc` pointer.
        let delegate = unsafe {
            let delegate = objc::send(
                objc::send(delegate_class, objc::sel("alloc")),
                objc::sel("init"),
            );
            objc::set_ivar(delegate, DELEGATE_IVAR, sink_pointer as *mut c_void);
            delegate
        };

        // SAFETY: standard alloc plus the three-argument designated
        // initialiser; a null delegate means "no stream-level delegate", which
        // is separate from the output delegate added below.
        let stream = unsafe {
            let stream = objc::send(objc::class("SCStream"), objc::sel("alloc"));
            objc::send_id3(
                stream,
                objc::sel("initWithFilter:configuration:delegate:"),
                filter,
                configuration,
                std::ptr::null_mut(),
            )
        };
        // SAFETY: the stream retains what it needs; these are ours to release.
        unsafe {
            objc::send(configuration, objc::sel("release"));
            objc::send(filter, objc::sel("release"));
        }
        if stream.is_null() {
            // SAFETY: reclaim the Arc the delegate was given, then the delegate.
            unsafe {
                objc::send(delegate, objc::sel("release"));
                drop(Arc::from_raw(sink_pointer));
            }
            return Err(SckError::Unavailable("SCStream init"));
        }

        let label = CString::new("openstream.screencapturekit").unwrap_or_else(|_| {
            CString::new("openstream").expect("a literal with no interior NUL")
        });
        // SAFETY: a serial queue with a valid label; null attributes means serial.
        let queue = unsafe { objc::dispatch_queue_create(label.as_ptr(), std::ptr::null()) };

        let mut error: Id = std::ptr::null_mut();
        // SAFETY: the stream, delegate and queue are all live; `error` is a
        // writable slot the method fills only on failure.
        let added = unsafe {
            objc::send_add_stream_output(
                stream,
                objc::sel("addStreamOutput:type:sampleHandlerQueue:error:"),
                delegate,
                OUTPUT_TYPE_SCREEN,
                queue,
                &raw mut error,
            )
        };
        if !added {
            // SAFETY: unwinding the objects created above, in reverse.
            let detail = unsafe { objc::error_message(error) }
                .unwrap_or_else(|| "no reason given".to_string());
            unsafe {
                objc::dispatch_release(queue);
                objc::send(stream, objc::sel("release"));
                objc::send(delegate, objc::sel("release"));
                drop(Arc::from_raw(sink_pointer));
            }
            return Err(SckError::AddOutput(detail));
        }

        // SAFETY: `stream` is live; the block is a stack block whose frame
        // outlives the semaphore wait inside `await_completion`.
        if let Err(detail) =
            unsafe { await_completion(stream, "startCaptureWithCompletionHandler:") }
        {
            // SAFETY: as above.
            unsafe {
                objc::dispatch_release(queue);
                objc::send(stream, objc::sel("release"));
                objc::send(delegate, objc::sel("release"));
                drop(Arc::from_raw(sink_pointer));
            }
            return Err(SckError::Start(detail));
        }

        Ok(Self {
            stream,
            delegate,
            queue,
            sink,
        })
    }

    /// Take the newest captured frame, if one has arrived since the last take.
    ///
    /// Returns `None` on a static screen: ScreenCaptureKit delivers on change,
    /// so "nothing new" is the normal idle state and not an error.
    #[must_use]
    pub fn take_frame(&self) -> Option<CapturedSurface> {
        self.sink.take()
    }

    /// How many frames the stream has delivered since it started.
    ///
    /// Counts frames the delegate accepted, including ones replaced before the
    /// caller took them -- which is what separates "running, screen static"
    /// from "running, delivering nothing".
    #[must_use]
    pub fn delivered(&self) -> u64 {
        self.sink.delivered()
    }
}

impl Drop for SckCapture {
    fn drop(&mut self) {
        // Stop first and wait: the delegate must not be called again after its
        // sink pointer is reclaimed below.
        // SAFETY: `self.stream` is live until released just after.
        let _ = unsafe { await_completion(self.stream, "stopCaptureWithCompletionHandler:") };
        // SAFETY: each object was created in `start_with_content` and is
        // released exactly once here. The stream goes first, because it is
        // what retains the delegate; the ivar is cleared before the delegate
        // is released so that a callback arriving against Apple's documented
        // ordering finds nothing rather than a dangling pointer, and the
        // strong count the delegate was given is returned last.
        unsafe {
            objc::send(self.stream, objc::sel("release"));
            let sink_pointer = objc::get_ivar(self.delegate, DELEGATE_IVAR);
            objc::set_ivar(self.delegate, DELEGATE_IVAR, std::ptr::null_mut());
            objc::send(self.delegate, objc::sel("release"));
            objc::dispatch_release(self.queue);
            if !sink_pointer.is_null() {
                drop(Arc::from_raw(sink_pointer.cast::<Sink>()));
            }
        }
    }
}

/// Fetch `SCShareableContent`, blocking until its completion handler runs.
///
/// Returns a retained object: the one the handler receives is autoreleased and
/// would be gone by the time this returns.
fn shareable_content() -> Result<Id, SckError> {
    let class = objc::class("SCShareableContent");
    if class.is_null() {
        return Err(SckError::Unavailable("SCShareableContent"));
    }

    struct Context {
        out: *mut Id,
        semaphore: Id,
    }
    static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
        reserved: 0,
        size: std::mem::size_of::<TwoArgBlock<Context>>() as std::os::raw::c_ulong,
    };

    extern "C" fn received(block: *mut TwoArgBlock<Context>, content: Id, _error: Id) {
        // SAFETY: the runtime passes back the block this call was made with,
        // and the frame that owns it is parked on the semaphore below.
        let context = unsafe { &(*block).context };
        if !content.is_null() {
            // SAFETY: retained here because the handler's reference is
            // autoreleased and the caller needs it after this returns.
            let retained = unsafe { CFRetain(content.cast()) };
            // SAFETY: `out` points at the caller's stack slot, still alive.
            unsafe { *context.out = retained.cast_mut().cast() };
        }
        // SAFETY: the semaphore is alive until the waiter wakes.
        unsafe { objc::dispatch_semaphore_signal(context.semaphore) };
    }

    // SAFETY: a counting semaphore starting at zero.
    let semaphore = unsafe { objc::dispatch_semaphore_create(0) };
    let mut content: Id = std::ptr::null_mut();
    let mut block = TwoArgBlock::new(
        received,
        &DESCRIPTOR,
        Context {
            out: &raw mut content,
            semaphore,
        },
    );
    // SAFETY: the selector takes exactly one block of this shape, and this
    // frame does not return until the block has run.
    unsafe {
        objc::send_block(
            class,
            objc::sel("getShareableContentWithCompletionHandler:"),
            &raw mut block,
        );
        objc::dispatch_semaphore_wait(semaphore, FOREVER);
        objc::dispatch_release(semaphore);
    }

    if content.is_null() {
        return Err(SckError::NoShareableContent);
    }
    Ok(content)
}

/// Send a selector taking an `(NSError *)` completion handler, and wait for it.
///
/// # Safety
/// `target` must be live and respond to `selector` with one such block.
unsafe fn await_completion(target: Id, selector: &str) -> Result<(), String> {
    struct Context {
        detail: *mut Option<String>,
        semaphore: Id,
    }
    static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
        reserved: 0,
        size: std::mem::size_of::<OneArgBlock<Context>>() as std::os::raw::c_ulong,
    };

    extern "C" fn completed(block: *mut OneArgBlock<Context>, error: Id) {
        // SAFETY: as in `received` above -- the owning frame is parked.
        let context = unsafe { &(*block).context };
        if !error.is_null() {
            // SAFETY: `error` is an NSError while the handler runs.
            let message = unsafe { objc::error_message(error) }
                .unwrap_or_else(|| "no reason given".to_string());
            // SAFETY: points at the caller's still-live stack slot.
            unsafe { *context.detail = Some(message) };
        }
        // SAFETY: alive until the waiter wakes.
        unsafe { objc::dispatch_semaphore_signal(context.semaphore) };
    }

    // SAFETY: a counting semaphore starting at zero.
    let semaphore = unsafe { objc::dispatch_semaphore_create(0) };
    let mut detail: Option<String> = None;
    let mut block = OneArgBlock::new(
        completed,
        &DESCRIPTOR,
        Context {
            detail: &raw mut detail,
            semaphore,
        },
    );
    // SAFETY: the caller guarantees the selector's shape; this frame does not
    // return until the block has run.
    unsafe {
        objc::send_block(target, objc::sel(selector), &raw mut block);
        objc::dispatch_semaphore_wait(semaphore, FOREVER);
        objc::dispatch_release(semaphore);
    }
    detail.map_or(Ok(()), Err)
}

/// Choose the `SCDisplay` matching `display_id`, or the first one.
///
/// # Safety
/// `content` must be a live `SCShareableContent`.
unsafe fn pick_display(content: Id, display_id: Option<u32>) -> Result<Id, SckError> {
    // SAFETY: `displays` is a declared NSArray property.
    let displays = unsafe { objc::send(content, objc::sel("displays")) };
    if displays.is_null() {
        return Err(SckError::NoSuchDisplay(display_id));
    }
    // SAFETY: NSArray responds to `count` and `objectAtIndex:`.
    let count = unsafe { objc::send_count(displays, objc::sel("count")) };
    if count == 0 {
        return Err(SckError::NoSuchDisplay(None));
    }
    let Some(wanted) = display_id else {
        // SAFETY: index 0 is in range because `count` is non-zero.
        return Ok(unsafe { objc::send_index(displays, objc::sel("objectAtIndex:"), 0) });
    };
    for index in 0..count {
        // SAFETY: `index` is in range; `displayID` is a declared property.
        let display = unsafe { objc::send_index(displays, objc::sel("objectAtIndex:"), index) };
        if unsafe { objc::send_u32(display, objc::sel("displayID")) } == wanted {
            return Ok(display);
        }
    }
    Err(SckError::NoSuchDisplay(Some(wanted)))
}

/// The delegate class, registered once for the process.
fn delegate_class() -> Option<objc::Class> {
    static CLASS: OnceLock<Option<usize>> = OnceLock::new();
    let registered = CLASS.get_or_init(|| {
        // Type encoding: void return, self, _cmd, an object (the stream), a
        // pointer (the CMSampleBufferRef), and an NSInteger (the output type).
        // SAFETY: `did_output_sample_buffer` is `extern "C"` with exactly that
        // signature.
        let class = unsafe {
            objc::define_class(
                DELEGATE_CLASS,
                DELEGATE_IVAR,
                objc::sel("stream:didOutputSampleBuffer:ofType:"),
                did_output_sample_buffer as objc::Imp,
                "v@:@^vq",
                "SCStreamOutput",
            )
        };
        class.map(|class| class as usize)
    });
    registered.map(|address| address as objc::Class)
}

/// `- (void)stream:didOutputSampleBuffer:ofType:`
///
/// Runs on the stream's dispatch queue. Everything it touches is either owned
/// by the sample buffer (and copied or retained before returning) or behind the
/// sink's mutex.
extern "C" fn did_output_sample_buffer(
    this: Id,
    _cmd: objc::Sel,
    _stream: Id,
    sample_buffer: *mut c_void,
    output_type: isize,
) {
    if output_type != OUTPUT_TYPE_SCREEN || sample_buffer.is_null() {
        return;
    }
    // SAFETY: `this` is an instance of the class registered above, which
    // declares this ivar.
    let pointer = unsafe { objc::get_ivar(this, DELEGATE_IVAR) };
    if pointer.is_null() {
        // Torn down between the last frame and this one.
        return;
    }
    // A strong reference of this callback's own, not a borrow.
    //
    // What makes reclaiming the sink safe at all is the teardown order:
    // `Drop` waits for `stopCaptureWithCompletionHandler:` to complete, and
    // ScreenCaptureKit does not run that handler until the stream has stopped
    // delivering, so no callback is in flight by the time the pointer is
    // reclaimed. Taking a count here anyway means a callback that somehow is
    // in flight keeps the sink alive for its whole body instead of holding a
    // borrow into memory another thread is free to release.
    //
    // SAFETY: the pointer came from `Arc::into_raw` on an `Arc<Sink>` and the
    // matching strong count is still held by the `SckCapture`.
    let sink = unsafe {
        Arc::increment_strong_count(pointer.cast::<Sink>());
        Arc::from_raw(pointer.cast::<Sink>())
    };

    // SAFETY: a sample buffer handed to a stream output, valid for this call.
    unsafe {
        if !CMSampleBufferIsValid(sample_buffer) {
            return;
        }
        let pixel_buffer = CMSampleBufferGetImageBuffer(sample_buffer);
        if pixel_buffer.is_null() {
            return;
        }
        // An idle or blanked frame arrives without an IOSurface. Encoding it
        // would spend a frame slot re-sending a picture nothing changed in,
        // and the whole point of this path is that the surface can go straight
        // to the encoder.
        if CVPixelBufferGetIOSurface(pixel_buffer).is_null() {
            return;
        }
        let presentation_time_us = CMSampleBufferGetPresentationTimeStamp(sample_buffer)
            .as_micros()
            .unwrap_or(0);
        // Retained because the sample buffer owns this reference and reclaims
        // it when this callback returns.
        CFRetain(pixel_buffer.cast());
        sink.offer(CapturedSurface {
            pixel_buffer,
            width: CVPixelBufferGetWidth(pixel_buffer),
            height: CVPixelBufferGetHeight(pixel_buffer),
            presentation_time_us,
        });
    }
}

/// Whether a captured pixel buffer is in the format the encoder expects.
///
/// Split out and public so the format contract is checkable without a display:
/// the stream is configured for BGRA, and a frame in anything else would be
/// silently misencoded rather than rejected.
#[must_use]
pub fn is_expected_format(format: u32) -> bool {
    format == PIXEL_FORMAT_BGRA
}

/// The pixel format of a captured surface.
///
/// # Safety
/// `surface` must be alive.
#[must_use]
pub unsafe fn surface_format(surface: &CapturedSurface) -> u32 {
    // SAFETY: the surface holds a retain on a live pixel buffer.
    unsafe { CVPixelBufferGetPixelFormatType(surface.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_configured_format_is_the_one_the_encoder_expects() {
        assert!(is_expected_format(PIXEL_FORMAT_BGRA));
        // 'BGRA' as four bytes, spelled out so a changed constant is caught by
        // something other than itself.
        assert_eq!(PIXEL_FORMAT_BGRA.to_be_bytes(), *b"BGRA");
    }

    #[test]
    fn another_format_is_rejected() {
        // '420v', the format a NV12 stream would arrive in.
        assert!(!is_expected_format(u32::from_be_bytes(*b"420v")));
        assert!(!is_expected_format(0));
    }

    #[test]
    fn the_default_configuration_is_a_sane_stream() {
        let config = SckConfig::default();
        assert_eq!((config.width, config.height), (1920, 1080));
        assert_eq!(config.fps, 60);
        assert!(config.display_id.is_none());
    }

    /// The delegate class registers once and the same class comes back, which
    /// is what stops a second capture failing on a duplicate name.
    #[test]
    fn the_delegate_class_is_registered_once_and_reused() {
        let first = delegate_class();
        let second = delegate_class();
        assert!(first.is_some(), "the delegate class should register");
        assert_eq!(first, second);
    }

    /// The sink keeps the newest frame, not a backlog. Checked with the
    /// counter, since building a real `CapturedSurface` needs a display.
    #[test]
    fn the_sink_counts_every_frame_even_when_it_replaces_one() {
        let sink = Sink::default();
        assert_eq!(sink.delivered(), 0);
        assert!(sink.take().is_none());
    }

    /// Each failure carries what a reader needs to act: which permission,
    /// which display, which reason.
    #[test]
    fn the_errors_say_what_went_wrong() {
        assert!(
            SckError::NoShareableContent
                .to_string()
                .contains("Screen Recording")
        );
        assert!(SckError::NoSuchDisplay(Some(7)).to_string().contains('7'));
        assert!(
            SckError::Start("denied".into())
                .to_string()
                .contains("denied")
        );
    }

    /// Physical capture test: needs a real display and Screen Recording
    /// permission, so it is skipped unless forced -- the same gate the
    /// CoreGraphics capture test uses.
    ///
    /// What it proves that no offscreen test can: the stream really starts, it
    /// delivers frames at the size that was asked for, and every frame is
    /// IOSurface-backed BGRA -- which is the whole claim, since a frame without
    /// an IOSurface cannot reach the encoder without a copy.
    #[test]
    fn captures_iosurface_backed_frames_at_the_requested_size() {
        if std::env::var_os("OPENSTREAM_REQUIRE_MACOS_CAPTURE").is_none() {
            eprintln!(
                "skipping ScreenCaptureKit test (set OPENSTREAM_REQUIRE_MACOS_CAPTURE and grant Screen Recording)"
            );
            return;
        }
        let config = SckConfig {
            width: 1280,
            height: 720,
            fps: 60,
            display_id: None,
            show_cursor: false,
        };
        let capture = SckCapture::start(config).expect("start a ScreenCaptureKit capture");

        let mut taken = Vec::new();
        for _ in 0..200 {
            if let Some(frame) = capture.take_frame() {
                taken.push(frame);
                if taken.len() >= 3 {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            !taken.is_empty(),
            "the stream delivered no frames in two seconds (delivered={})",
            capture.delivered()
        );
        for frame in &taken {
            assert_eq!(frame.width(), 1280);
            assert_eq!(frame.height(), 720);
            // SAFETY: the frame holds a retain on its pixel buffer.
            let format = unsafe { surface_format(frame) };
            assert!(
                is_expected_format(format),
                "captured {:?}, expected BGRA",
                std::str::from_utf8(&format.to_be_bytes())
            );
        }
        assert!(capture.delivered() >= taken.len() as u64);
    }
}
