mod bridge;
mod recipe;

use vmi::{
    Va, VmiContext, VmiError,
    arch::amd64::{Amd64, Registers},
    driver::VmiFullDriver,
    os::windows::WindowsOs,
    utils::injector::RecipeExecutor,
};

pub use self::bridge::{FileTransferBridge, FileTransferStatus};
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
    state: FileTransferState<Driver>,
}

impl<Driver> FileTransfer<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Marks a file for transfer without allocating guest or host resources.
    pub fn new(handle: u64, file_object: Va, path: String) -> Self {
        Self {
            handle,
            file_object,
            path,
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
    pub fn start(&mut self) {
        assert!(
            matches!(self.state, FileTransferState::Pending),
            "file transfer started more than once"
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
        let executor = match &mut self.state {
            FileTransferState::Executing { executor } => executor,
            FileTransferState::Pending => panic!("pending file transfer cannot execute"),
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
