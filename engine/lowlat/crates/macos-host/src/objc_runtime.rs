//! The slice of the Objective-C runtime the ScreenCaptureKit capture needs.
//!
//! Everything else this crate talks to -- CoreGraphics, CoreVideo, CoreMedia --
//! is a C API that binds directly. ScreenCaptureKit is not: `SCStream` is
//! Objective-C, with no C entry point, so reaching it means sending messages
//! and declaring a delegate class at runtime.
//!
//! This is hand-rolled rather than taken from a crate. The alternative pulls an
//! Objective-C binding stack into a tree whose whole macOS surface is currently
//! direct framework FFI, past a dependency policy that exists to keep the link
//! graph small and auditable, for a handful of selectors. What is here is the
//! handful.
//!
//! # Sending messages
//!
//! `objc_msgSend` has no single signature: the caller casts it to the shape of
//! the method being called, and the ABI does the rest. Getting that cast wrong
//! is undefined behaviour, so every send in this crate goes through one of the
//! typed helpers below rather than transmuting at the call site -- the casts
//! live in one place where they can be read against the method declarations.
//!
//! # Blocks
//!
//! Two ScreenCaptureKit entry points take completion blocks. A block is a
//! struct with a function pointer and an isa, and the stack variety is valid
//! only while its frame lives -- so every block here is paired with a semaphore
//! the caller waits on before returning, which is also the synchronous setup
//! the capture wants.

#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString, c_void};
use std::os::raw::{c_char, c_int, c_ulong};

/// An Objective-C object pointer.
pub(crate) type Id = *mut c_void;
/// A selector.
pub(crate) type Sel = *const c_void;
/// A class (also a valid [`Id`]).
pub(crate) type Class = *mut c_void;
/// A method implementation.
pub(crate) type Imp = *const c_void;

#[link(name = "objc", kind = "dylib")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn objc_getProtocol(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_msgSend();
    fn objc_allocateClassPair(superclass: Class, name: *const c_char, extra: usize) -> Class;
    fn objc_registerClassPair(cls: Class);
    fn class_addMethod(cls: Class, name: Sel, imp: Imp, types: *const c_char) -> bool;
    fn class_addProtocol(cls: Class, protocol: Id) -> bool;
    /// Only [`implements`] uses this, and only tests use that.
    #[cfg(test)]
    fn class_getInstanceMethod(cls: Class, name: Sel) -> *mut c_void;
    fn class_addIvar(
        cls: Class,
        name: *const c_char,
        size: usize,
        alignment: u8,
        types: *const c_char,
    ) -> bool;
    fn object_getInstanceVariable(
        object: Id,
        name: *const c_char,
        out: *mut *mut c_void,
    ) -> *mut c_void;
    fn object_setInstanceVariable(
        object: Id,
        name: *const c_char,
        value: *mut c_void,
    ) -> *mut c_void;
}

#[link(name = "System", kind = "dylib")]
unsafe extern "C" {
    pub(crate) fn dispatch_semaphore_create(value: isize) -> Id;
    pub(crate) fn dispatch_semaphore_wait(semaphore: Id, timeout: u64) -> isize;
    pub(crate) fn dispatch_semaphore_signal(semaphore: Id) -> isize;
    pub(crate) fn dispatch_queue_create(label: *const c_char, attributes: *const c_void) -> Id;
    pub(crate) fn dispatch_release(object: Id);
    static _NSConcreteStackBlock: [*const c_void; 32];
}

/// `DISPATCH_TIME_FOREVER`.
pub(crate) const FOREVER: u64 = u64::MAX;

/// Look up a class by name. Null if the runtime does not have it, which is how
/// a framework missing at runtime presents.
pub(crate) fn class(name: &str) -> Class {
    let Ok(name) = CString::new(name) else {
        return std::ptr::null_mut();
    };
    // SAFETY: FFI with a valid NUL-terminated name; returns null if unknown.
    unsafe { objc_getClass(name.as_ptr()) }
}

/// Register (or look up) a selector by name.
pub(crate) fn sel(name: &str) -> Sel {
    let Ok(name) = CString::new(name) else {
        return std::ptr::null();
    };
    // SAFETY: FFI with a valid NUL-terminated name.
    unsafe { sel_registerName(name.as_ptr()) }
}

/// Look up a protocol by name. Null if unknown.
pub(crate) fn protocol(name: &str) -> Id {
    let Ok(name) = CString::new(name) else {
        return std::ptr::null_mut();
    };
    // SAFETY: FFI with a valid NUL-terminated name.
    unsafe { objc_getProtocol(name.as_ptr()) }
}

// The shapes below are each written out next to the method family they are
// for, rather than generated, so a cast can be read against Apple's
// declaration without expanding a macro first.

/// `- (id)selector`
///
/// # Safety
/// `receiver` must respond to `selector` with no arguments, returning an object.
pub(crate) unsafe fn send(receiver: Id, selector: Sel) -> Id {
    // SAFETY: the caller guarantees the shape; this is the standard cast.
    let send: extern "C" fn(Id, Sel) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector)
}

/// `- (id)selector:(id)a other:(id)b`
///
/// # Safety
/// `receiver` must respond to `selector` with two object arguments.
pub(crate) unsafe fn send_id2(receiver: Id, selector: Sel, a: Id, b: Id) -> Id {
    // SAFETY: as above.
    let send: extern "C" fn(Id, Sel, Id, Id) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector, a, b)
}

/// `- (id)selector:(id)a other:(id)b third:(id)c`
///
/// # Safety
/// `receiver` must respond to `selector` with three object arguments.
pub(crate) unsafe fn send_id3(receiver: Id, selector: Sel, a: Id, b: Id, c: Id) -> Id {
    // SAFETY: as above.
    let send: extern "C" fn(Id, Sel, Id, Id, Id) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector, a, b, c)
}

/// `- (id)objectAtIndex:(NSUInteger)index`
///
/// # Safety
/// `receiver` must respond to `selector` with one `NSUInteger` argument.
pub(crate) unsafe fn send_index(receiver: Id, selector: Sel, index: usize) -> Id {
    // SAFETY: as above.
    let send: extern "C" fn(Id, Sel, usize) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector, index)
}

/// `- (NSUInteger)selector`
///
/// # Safety
/// `receiver` must respond to `selector` returning an `NSUInteger`.
pub(crate) unsafe fn send_count(receiver: Id, selector: Sel) -> usize {
    // SAFETY: as above.
    let send: extern "C" fn(Id, Sel) -> usize =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector)
}

/// `- (uint32_t)selector`
///
/// # Safety
/// `receiver` must respond to `selector` returning a 32-bit integer.
pub(crate) unsafe fn send_u32(receiver: Id, selector: Sel) -> u32 {
    // SAFETY: as above.
    let send: extern "C" fn(Id, Sel) -> u32 =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector)
}

/// `- (void)selector:(NSUInteger)value`
///
/// # Safety
/// `receiver` must respond to `selector` with one `NSUInteger` argument.
pub(crate) unsafe fn send_set_usize(receiver: Id, selector: Sel, value: usize) {
    // SAFETY: as above.
    let send: extern "C" fn(Id, Sel, usize) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector, value);
}

/// `- (void)selector:(uint32_t)value`
///
/// # Safety
/// `receiver` must respond to `selector` with one 32-bit integer argument.
pub(crate) unsafe fn send_set_u32(receiver: Id, selector: Sel, value: u32) {
    // SAFETY: as above.
    let send: extern "C" fn(Id, Sel, u32) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector, value);
}

/// `- (void)selector:(BOOL)value`
///
/// # Safety
/// `receiver` must respond to `selector` with one `BOOL` argument.
pub(crate) unsafe fn send_set_bool(receiver: Id, selector: Sel, value: bool) {
    // SAFETY: as above.
    let send: extern "C" fn(Id, Sel, bool) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector, value);
}

/// `- (void)selector:(CMTime)value`
///
/// # Safety
/// `receiver` must respond to `selector` with one `CMTime` argument.
pub(crate) unsafe fn send_set_time(receiver: Id, selector: Sel, value: CmTime) {
    // SAFETY: as above. `CMTime` is a by-value struct in registers.
    let send: extern "C" fn(Id, Sel, CmTime) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector, value);
}

/// `- (BOOL)addStreamOutput:(id)output type:(NSInteger)type sampleHandlerQueue:(dispatch_queue_t)queue error:(NSError **)error`
///
/// # Safety
/// `receiver` must be an `SCStream`; `error` must be a writable slot.
pub(crate) unsafe fn send_add_stream_output(
    receiver: Id,
    selector: Sel,
    output: Id,
    kind: isize,
    queue: Id,
    error: *mut Id,
) -> bool {
    // SAFETY: as above.
    let send: extern "C" fn(Id, Sel, Id, isize, Id, *mut Id) -> bool =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector, output, kind, queue, error)
}

/// `CMTime`, laid out as CoreMedia declares it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CmTime {
    pub(crate) value: i64,
    pub(crate) timescale: i32,
    pub(crate) flags: u32,
    pub(crate) epoch: i64,
}

/// `kCMTimeFlags_Valid`.
pub(crate) const CM_TIME_VALID: u32 = 1;

impl CmTime {
    /// One frame interval for `fps` frames per second.
    ///
    /// Expressed as `1/fps` rather than a microsecond count so the rate is
    /// exact: 60 fps is 1/60, not a rounded 16 666 us that drifts.
    #[must_use]
    pub(crate) const fn frame_interval(fps: u32) -> Self {
        Self {
            value: 1,
            timescale: if fps == 0 { 1 } else { fps as i32 },
            flags: CM_TIME_VALID,
            epoch: 0,
        }
    }

    /// The time in microseconds, or `None` if the time is not valid or has no
    /// timescale to divide by.
    #[must_use]
    pub(crate) const fn as_micros(self) -> Option<i64> {
        if self.flags & CM_TIME_VALID == 0 || self.timescale == 0 {
            return None;
        }
        Some(self.value.saturating_mul(1_000_000) / self.timescale as i64)
    }
}

/// A block whose invoke function takes one object argument.
///
/// Laid out exactly as the ABI expects, and deliberately a *stack* block: the
/// caller signals a semaphore from inside the block and does not return until
/// it has, so the block never outlives its frame.
#[repr(C)]
pub(crate) struct OneArgBlock<T> {
    pub(crate) isa: *const c_void,
    pub(crate) flags: c_int,
    pub(crate) reserved: c_int,
    pub(crate) invoke: extern "C" fn(*mut Self, Id),
    pub(crate) descriptor: *const BlockDescriptor,
    pub(crate) context: T,
}

/// A block whose invoke function takes two object arguments.
#[repr(C)]
pub(crate) struct TwoArgBlock<T> {
    pub(crate) isa: *const c_void,
    pub(crate) flags: c_int,
    pub(crate) reserved: c_int,
    pub(crate) invoke: extern "C" fn(*mut Self, Id, Id),
    pub(crate) descriptor: *const BlockDescriptor,
    pub(crate) context: T,
}

/// The descriptor every block points at: its size, and nothing else for a
/// block with no copy/dispose helpers (which is every block here, because the
/// captures are plain pointers).
#[repr(C)]
pub(crate) struct BlockDescriptor {
    pub(crate) reserved: c_ulong,
    pub(crate) size: c_ulong,
}

// SAFETY: a descriptor is immutable data read by the runtime.
unsafe impl Sync for BlockDescriptor {}

impl<T> OneArgBlock<T> {
    /// Build a stack block around `context`.
    pub(crate) fn new(
        invoke: extern "C" fn(*mut Self, Id),
        descriptor: &'static BlockDescriptor,
        context: T,
    ) -> Self {
        Self {
            // SAFETY: reading the address of the runtime's stack-block class.
            isa: unsafe { _NSConcreteStackBlock.as_ptr().cast() },
            flags: 0,
            reserved: 0,
            invoke,
            descriptor,
            context,
        }
    }
}

impl<T> TwoArgBlock<T> {
    /// Build a stack block around `context`.
    pub(crate) fn new(
        invoke: extern "C" fn(*mut Self, Id, Id),
        descriptor: &'static BlockDescriptor,
        context: T,
    ) -> Self {
        Self {
            // SAFETY: reading the address of the runtime's stack-block class.
            isa: unsafe { _NSConcreteStackBlock.as_ptr().cast() },
            flags: 0,
            reserved: 0,
            invoke,
            descriptor,
            context,
        }
    }
}

/// Send a message whose single argument is a block pointer.
///
/// # Safety
/// `receiver` must respond to `selector` with one block argument of this shape.
pub(crate) unsafe fn send_block<B>(receiver: Id, selector: Sel, block: *mut B) {
    // SAFETY: a block is passed as its pointer, like any object.
    let send: extern "C" fn(Id, Sel, *mut B) =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    send(receiver, selector, block);
}

/// Define a subclass of `NSObject` at runtime, with one pointer-sized ivar and
/// one method, conforming to `protocol_name`.
///
/// Returns `None` if the runtime refuses the name -- which is what happens when
/// a class of that name already exists, so callers register once and keep the
/// result.
///
/// # Safety
///
/// `imp` must be an `extern "C"` function whose signature matches `types` and
/// the method's declaration, taking `(Id, Sel, ...)`.
pub(crate) unsafe fn define_class(
    name: &str,
    ivar: &str,
    methods: &[(Sel, Imp, &str)],
    protocol_names: &[&str],
) -> Option<Class> {
    let class_name = CString::new(name).ok()?;
    let ivar_name = CString::new(ivar).ok()?;
    let pointer_encoding = CString::new("^v").ok()?;
    let superclass = class("NSObject");
    if superclass.is_null() {
        return None;
    }
    // SAFETY: FFI. A duplicate name returns null, which is handled.
    let cls = unsafe { objc_allocateClassPair(superclass, class_name.as_ptr(), 0) };
    if cls.is_null() {
        return None;
    }
    // SAFETY: the class is still under construction, which is when ivars,
    // methods and protocols may be added.
    unsafe {
        class_addIvar(
            cls,
            ivar_name.as_ptr(),
            std::mem::size_of::<*mut c_void>(),
            // Alignment is given as log2 of the byte alignment. A pointer's
            // alignment is 8 on every target this builds for, so the log2 is 3
            // and the narrowing cannot lose anything; it is written with
            // `try_into` rather than `as` so a future target that breaks that
            // assumption fails loudly instead of silently wrapping.
            u8::try_from(std::mem::align_of::<*mut c_void>().trailing_zeros()).ok()?,
            pointer_encoding.as_ptr(),
        );
        for (selector, imp, types) in methods {
            let Ok(type_encoding) = CString::new(*types) else {
                continue;
            };
            class_addMethod(cls, *selector, *imp, type_encoding.as_ptr());
        }
        // A protocol the runtime does not know about is not an error: it means
        // this macOS does not declare it, and the methods are still installed
        // and still called. ScreenCaptureKit dispatches by selector.
        for protocol_name in protocol_names {
            let proto = protocol(protocol_name);
            if !proto.is_null() {
                class_addProtocol(cls, proto);
            }
        }
        objc_registerClassPair(cls);
    }
    Some(cls)
}

/// Whether a class actually implements a selector.
///
/// `class_addMethod` returns false for a name already taken and simply does
/// nothing for a type encoding the runtime dislikes, so "the code that adds the
/// method ran" is not the same as "the method is there". This is how a test can
/// tell the difference -- and the difference matters, because a delegate method
/// that was never installed is not an error at runtime either. The framework
/// checks `respondsToSelector:`, finds nothing, and silently never calls it.
///
/// Test-only: nothing in the running host asks this, and a production build
/// that carried it would carry a use of the runtime it never makes.
#[cfg(test)]
#[must_use]
pub(crate) fn implements(cls: Class, selector: Sel) -> bool {
    if cls.is_null() {
        return false;
    }
    // SAFETY: FFI against a registered class; a missing method returns null.
    !unsafe { class_getInstanceMethod(cls, selector) }.is_null()
}

/// Store a raw pointer in an object's ivar.
///
/// # Safety
/// `object` must be an instance of a class declaring a pointer ivar of this name.
pub(crate) unsafe fn set_ivar(object: Id, name: &str, value: *mut c_void) {
    let Ok(name) = CString::new(name) else {
        return;
    };
    // SAFETY: the caller guarantees the ivar exists and is pointer-sized.
    unsafe { object_setInstanceVariable(object, name.as_ptr(), value) };
}

/// Read a raw pointer back out of an object's ivar.
///
/// # Safety
/// `object` must be an instance of a class declaring a pointer ivar of this name.
pub(crate) unsafe fn get_ivar(object: Id, name: &str) -> *mut c_void {
    let Ok(name) = CString::new(name) else {
        return std::ptr::null_mut();
    };
    let mut value: *mut c_void = std::ptr::null_mut();
    // SAFETY: as above; `value` is a writable slot.
    unsafe { object_getInstanceVariable(object, name.as_ptr(), &raw mut value) };
    value
}

/// An `NSError`'s `localizedDescription`, for a message a human can act on.
///
/// # Safety
/// `error` must be null or a live `NSError`.
pub(crate) unsafe fn error_message(error: Id) -> Option<String> {
    if error.is_null() {
        return None;
    }
    // SAFETY: `localizedDescription` returns an autoreleased NSString.
    let description = unsafe { send(error, sel("localizedDescription")) };
    if description.is_null() {
        return None;
    }
    // SAFETY: `UTF8String` returns a NUL-terminated buffer owned by the string,
    // which outlives this copy.
    let utf8: extern "C" fn(Id, Sel) -> *const c_char =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    let pointer = utf8(description, sel("UTF8String"));
    if pointer.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated C string from the runtime.
    Some(
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame interval has to be exact: 60 fps expressed in microseconds
    /// rounds to 16 666 and drifts a frame every few seconds.
    #[test]
    fn a_frame_interval_is_an_exact_fraction() {
        let interval = CmTime::frame_interval(60);
        assert_eq!(interval.value, 1);
        assert_eq!(interval.timescale, 60);
        assert_eq!(interval.flags, CM_TIME_VALID);
    }

    /// A zero rate would be a divide by zero inside CoreMedia.
    #[test]
    fn a_zero_frame_rate_does_not_produce_a_zero_timescale() {
        assert_eq!(CmTime::frame_interval(0).timescale, 1);
    }

    #[test]
    fn a_valid_time_converts_to_microseconds() {
        let time = CmTime {
            value: 90_000,
            timescale: 90_000,
            flags: CM_TIME_VALID,
            epoch: 0,
        };
        assert_eq!(time.as_micros(), Some(1_000_000));
    }

    /// An invalid time must not be read as "zero microseconds": a frame
    /// stamped at the epoch and a frame with no stamp are different things,
    /// and the pipeline has to be able to tell them apart.
    #[test]
    fn an_invalid_time_has_no_microseconds() {
        let invalid = CmTime {
            value: 12_345,
            timescale: 1_000,
            flags: 0,
            epoch: 0,
        };
        assert_eq!(invalid.as_micros(), None);

        let no_timescale = CmTime {
            value: 12_345,
            timescale: 0,
            flags: CM_TIME_VALID,
            epoch: 0,
        };
        assert_eq!(no_timescale.as_micros(), None);
    }

    /// An unknown class is reported as null rather than trapping, so a
    /// framework missing at runtime degrades to "capture unavailable".
    #[test]
    fn an_unknown_class_is_null() {
        assert!(class("OpenStreamNoSuchClassExists").is_null());
    }

    #[test]
    fn a_name_with_an_interior_nul_does_not_reach_the_runtime() {
        assert!(class("bad\0name").is_null());
        assert!(sel("bad\0selector").is_null());
        assert!(protocol("bad\0protocol").is_null());
    }

    /// `NSObject` is always present, so this checks the lookup really works
    /// rather than only that a bad name fails.
    #[test]
    fn a_known_class_and_selector_resolve() {
        assert!(!class("NSObject").is_null());
        assert!(!sel("alloc").is_null());
    }
}
