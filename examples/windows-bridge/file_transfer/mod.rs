mod bridge;
mod recipe;

use std::path::{Path, PathBuf};

use vmi::{
    Va, VmiContext, VmiError,
    arch::amd64::{Amd64, Registers},
    driver::VmiFullDriver,
    os::{ProcessId, ThreadObject, windows::WindowsOs},
    utils::injector::RecipeExecutor,
};

pub use self::bridge::{FileTransferBridge, FileTransferBridgeState};
use self::recipe::{FileTransferRecipeData, file_transfer_recipe};

/// Lifecycle of one file marked by `NtWriteFile` and transferred at `NtClose`.
enum FileTransferState<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    Pending,
    Executing {
        executor: RecipeExecutor<WindowsOs<Driver>, FileTransferRecipeData>,
    },
}

/// A process-local file transfer that moves to the closing thread while executing.
pub struct FileTransfer<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    handle: u64,
    file_object: Va,
    path: String,
    output_path: PathBuf,
    state: FileTransferState<Driver>,
}

impl<Driver> FileTransfer<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Marks a file for transfer without allocating guest or host resources.
    pub fn new(
        process_id: ProcessId,
        handle: u64,
        file_object: Va,
        path: String,
        output_directory: &Path,
    ) -> Self {
        let output_path =
            output_directory.join(output_filename(process_id, handle, file_object, &path));

        Self {
            handle,
            file_object,
            path,
            output_path,
            state: FileTransferState::Pending,
        }
    }

    pub fn handle(&self) -> u64 {
        self.handle
    }

    pub fn file_object(&self) -> Va {
        self.file_object
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Starts synchronous execution in the thread that is about to close the handle.
    pub fn start(&mut self, thread_object: ThreadObject, bridge: &mut FileTransferBridgeState) {
        assert!(
            matches!(self.state, FileTransferState::Pending),
            "file transfer started more than once"
        );

        bridge.start(
            thread_object,
            self.handle,
            self.path.clone(),
            self.output_path.clone(),
        );
        self.state = FileTransferState::Executing {
            executor: RecipeExecutor::new(file_transfer_recipe(self.handle)),
        };
    }

    /// Advances the injection recipe on the current thread.
    pub fn execute(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
    ) -> Result<Option<Registers>, VmiError> {
        let FileTransferState::Executing { executor } = &mut self.state
        else {
            panic!("pending file transfer cannot execute");
        };

        executor.execute(vmi)
    }

    pub fn done(&self) -> bool {
        match &self.state {
            FileTransferState::Pending => false,
            FileTransferState::Executing { executor } => executor.done(),
        }
    }
}

/// Produces a flat host filename; guest path components never become host directories.
fn output_filename(process_id: ProcessId, handle: u64, file_object: Va, path: &str) -> String {
    let basename = path
        .rsplit(['\\', '/'])
        .find(|component| !component.is_empty())
        .unwrap_or("file");
    let basename = basename
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            }
            else {
                '_'
            }
        })
        .collect::<String>();
    let basename = if basename.is_empty() {
        "file"
    }
    else {
        &basename
    };

    format!(
        "{}-{handle:016x}-{:016x}-{basename}",
        process_id, file_object.0
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_filename_flattens_guest_path() {
        let filename = output_filename(
            ProcessId(42),
            0x88,
            Va(0x1234),
            r"\Device\HarddiskVolume2\Users\John\report:final.txt",
        );

        assert_eq!(
            filename,
            "42-0000000000000088-0000000000001234-report_final.txt"
        );
        assert!(!filename.contains('/'));
        assert!(!filename.contains('\\'));
    }
}
