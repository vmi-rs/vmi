mod bridge;
mod recipe;

use vmi::{
    Va, VmiContext, VmiError,
    arch::amd64::{Amd64, Registers},
    driver::VmiFullDriver,
    os::windows::WindowsOs,
    utils::{injector::RecipeExecutor, shellcode::KernelShellcodeRecipeData},
};

#[expect(unused_imports)]
pub use self::bridge::{FileTransferBridge, FileTransferStatus};
use self::recipe::file_transfer_recipe;

/// State of a file marked by `NtWriteFile` and transferred during `NtClose`.
#[expect(
    clippy::large_enum_variant,
    reason = "only a handful of transfers exist at a time, so boxing the recipe \
              executor would add an allocation without improving readability"
)]
enum FileTransferState<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Transfer has been created but not yet started.
    Pending,

    /// Transfer is currently being executed.
    Executing(RecipeExecutor<WindowsOs<Driver>, KernelShellcodeRecipeData<WindowsOs<Driver>>>),
}

/// File transfer that runs on the thread executing `NtClose`.
pub struct FileTransfer<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Process-local handle of the file being transferred.
    handle: u64,

    /// Guest `_FILE_OBJECT` address of the file being transferred.
    file_object: Va,

    /// Guest path of the file being transferred.
    path: String,

    /// Current state of the file transfer.
    state: FileTransferState<Driver>,
}

impl<Driver> FileTransfer<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Creates a pending transfer.
    pub fn new(handle: u64, file_object: Va, path: String) -> Self {
        Self {
            handle,
            file_object,
            path,
            state: FileTransferState::Pending,
        }
    }

    /// Returns the process-local file handle.
    pub fn handle(&self) -> u64 {
        self.handle
    }

    /// Returns the guest `_FILE_OBJECT` address.
    pub fn file_object(&self) -> Va {
        self.file_object
    }

    /// Returns the file's guest path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Starts the transfer on the thread that is about to close the file handle.
    pub fn start(&mut self) {
        assert!(
            matches!(self.state, FileTransferState::Pending),
            "file transfer started more than once"
        );

        self.state =
            FileTransferState::Executing(RecipeExecutor::new(file_transfer_recipe(self.handle)));
    }

    /// Advances the `file-transfer` recipe on the current thread.
    pub fn execute(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
    ) -> Result<Option<Registers>, VmiError> {
        let executor = match &mut self.state {
            FileTransferState::Executing(executor) => executor,
            FileTransferState::Pending => panic!("pending file transfer cannot execute"),
        };

        executor.execute(vmi)
    }

    /// Returns whether the `file-transfer` recipe has finished.
    pub fn done(&self) -> bool {
        match &self.state {
            FileTransferState::Pending => false,
            FileTransferState::Executing(executor) => executor.done(),
        }
    }
}
