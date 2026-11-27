//! Intercept Finder drops before WebKit or Tauri can process their pasteboard.

use std::{ffi::CStr, os::unix::ffi::OsStrExt, path::PathBuf};

use objc2::{
    define_class, msg_send,
    rc::Retained,
    runtime::{Bool, NSObjectProtocol, ProtocolObject},
    ClassType, DeclaredClass, MainThreadMarker, MainThreadOnly, Message,
};
use objc2_app_kit::{
    NSAutoresizingMaskOptions, NSDragOperation, NSDraggingDestination, NSDraggingInfo,
    NSPasteboardTypeFileURL, NSView,
};
use objc2_foundation::{NSArray, NSURL};
use tauri::{AppHandle, Emitter, Manager, WebviewWindow};

use super::SharedScrubber;

const DROP_EVENT: &str = "scrubber://drop";

pub(crate) fn install(window: &WebviewWindow) -> tauri::Result<()> {
    let app = window.app_handle().clone();
    window.with_webview(move |platform| {
        let mtm = MainThreadMarker::new().expect("Tauri installs the drop view on the main thread");
        // PlatformWebview::inner borrows a live WKWebView, which inherits NSView.
        let view = unsafe { platform.inner().cast::<NSView>().as_ref() }
            .expect("native drop setup requires a webview");
        // The parent holds the webview while the new container is attached.
        let parent = unsafe { view.superview() }.expect("the webview must be attached");
        let view = view.retain();
        let destination = DropView::new(app, view.frame(), mtm);
        destination.setAutoresizingMask(view.autoresizingMask());

        // With the Tauri handler disabled, Wry otherwise falls through to
        // WebKit's drag handler. Register file drops only on our native view.
        let native_window = view.window();
        let first_responder = native_window
            .as_ref()
            .and_then(|window| window.firstResponder());
        view.removeFromSuperview();
        parent.addSubview(&destination);
        view.setFrame(destination.bounds());
        view.setAutoresizingMask(
            NSAutoresizingMaskOptions::ViewWidthSizable
                | NSAutoresizingMaskOptions::ViewHeightSizable,
        );
        destination.addSubview(&view);
        view.unregisterDraggedTypes();
        if let (Some(window), Some(responder)) = (native_window, first_responder) {
            window.makeFirstResponder(Some(&responder));
        }
        destination
            .registerForDraggedTypes(&NSArray::from_slice(&[unsafe { NSPasteboardTypeFileURL }]));
    })
}

type DragInfo = ProtocolObject<dyn NSDraggingInfo>;

define_class!(
    #[unsafe(super(NSView))]
    #[name = "RedactPadDropView"]
    #[thread_kind = MainThreadOnly]
    #[ivars = AppHandle]
    struct DropView;

    unsafe impl NSObjectProtocol for DropView {}

    unsafe impl NSDraggingDestination for DropView {
        #[unsafe(method(draggingEntered:))]
        fn dragging_entered(&self, sender: &DragInfo) -> NSDragOperation {
            sender.draggingSourceOperationMask() & NSDragOperation::Copy
        }

        #[unsafe(method(draggingUpdated:))]
        fn dragging_updated(&self, sender: &DragInfo) -> NSDragOperation {
            sender.draggingSourceOperationMask() & NSDragOperation::Copy
        }

        #[unsafe(method(prepareForDragOperation:))]
        fn prepare(&self, _sender: &DragInfo) -> Bool {
            Bool::YES
        }

        #[unsafe(method(performDragOperation:))]
        fn perform(&self, sender: &DragInfo) -> Bool {
            let path = single_file_path(sender);
            let app = self.ivars();
            match app.state::<SharedScrubber>().ingest_drop(path.as_slice()) {
                Ok(summary) => {
                    let _ = app.emit(DROP_EVENT, summary);
                    Bool::YES
                }
                Err(error) => {
                    let _ = app.emit(DROP_EVENT, error);
                    Bool::NO
                }
            }
        }
    }
);

impl DropView {
    fn new(
        app: AppHandle,
        frame: objc2_foundation::NSRect,
        mtm: MainThreadMarker,
    ) -> Retained<Self> {
        let view = Self::alloc(mtm).set_ivars(app);
        // The allocated receiver and frame match NSView's designated initializer.
        unsafe { msg_send![super(view), initWithFrame: frame] }
    }
}

fn single_file_path(sender: &DragInfo) -> Option<PathBuf> {
    let pasteboard = sender.draggingPasteboard();
    if pasteboard.pasteboardItems()?.len() != 1 {
        return None;
    }
    // NSURL resolves its documented pasteboard representation without JS.
    let classes = NSArray::from_slice(&[NSURL::class()]);
    let items = unsafe { pasteboard.readObjectsForClasses_options(&classes, None) }?;
    if items.len() != 1 {
        return None;
    }
    let item = items.objectAtIndex(0);
    let url = item.downcast_ref::<NSURL>()?;
    if !url.isFileURL()
        || url.host().is_some_and(|host| {
            let host = host.to_string();
            !host.is_empty() && !host.eq_ignore_ascii_case("localhost")
        })
    {
        return None;
    }
    let url = url.filePathURL()?;
    // The representation is valid for the lifetime of the retained NSURL.
    let bytes = unsafe { CStr::from_ptr(url.fileSystemRepresentation().as_ptr()) }.to_bytes();
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
    path.is_absolute().then_some(path)
}
