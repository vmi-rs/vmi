use std::collections::HashMap;

use vmi_core::{os::VmiOs, Architecture, Hex, Registers, Va, VmiContext, VmiDriver, VmiError};

/// The control flow of a recipe step.
pub enum RecipeControlFlow {
    /// Continue to the next step.
    Continue,

    /// Stop executing the recipe.
    Break,

    /// Repeat the current step.
    Repeat,

    /// Skip the next step.
    Skip,

    /// Jump to a specific step.
    Goto(usize),
}

/// A function that executes a single step in an injection recipe.
pub type RecipeStepFn<Driver, Os, T> = Box<
    dyn Fn(&mut RecipeContext<'_, Driver, Os, T>) -> Result<RecipeControlFlow, VmiError>
        + Send
        + Sync
        + 'static,
>;

/// A cache of symbols for a single image.
/// The key is the symbol name and the value is the virtual address.
pub type SymbolCache = HashMap<String, Va>;

/// A cache of symbols for multiple images.
/// The key is the image filename and the value is the symbol cache.
pub type ImageSymbolCache = HashMap<String, SymbolCache>;

/// A sequence of injection steps to be executed in order.
pub struct Recipe<Driver, Os, T>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The ordered list of steps to execute.
    pub(super) steps: Vec<RecipeStepFn<Driver, Os, T>>,

    /// User-provided data shared between steps.
    pub(super) data: T,
}

impl<Driver, Os, T> Recipe<Driver, Os, T>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Creates a new recipe with the given data.
    pub fn new(data: T) -> Self {
        Self {
            steps: Vec::new(),
            data,
        }
    }

    /// Adds a new step to the recipe.
    pub fn step<F>(mut self, f: F) -> Self
    where
        F: Fn(&mut RecipeContext<'_, Driver, Os, T>) -> Result<RecipeControlFlow, VmiError>
            + Send
            + Sync
            + 'static,
    {
        self.steps.push(Box::new(f));
        self
    }
}

/// Context provided to each recipe step during execution.
pub struct RecipeContext<'a, Driver, Os, T>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI context.
    pub vmi: &'a VmiContext<'a, Driver, Os>,

    /// The CPU registers.
    pub registers: &'a mut <<Driver as VmiDriver>::Architecture as Architecture>::Registers,

    /// User-provided data shared between steps.
    pub data: &'a mut T,

    /// Cache of resolved symbols for each module.
    pub cache: &'a mut ImageSymbolCache,
}

/// Manages the execution of a recipe's steps.
pub struct RecipeExecutor<Driver, Os, T>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The recipe being executed.
    recipe: Recipe<Driver, Os, T>,

    /// Cache of resolved symbols per module.
    cache: ImageSymbolCache,

    /// Original state of CPU registers to restore after completion.
    original_registers: Option<<Driver::Architecture as Architecture>::Registers>,

    /// Index of the current step being executed.
    index: Option<usize>,

    /// The previous stack pointer value.
    previous_stack_pointer: Option<Va>,
}

impl<Driver, Os, T> RecipeExecutor<Driver, Os, T>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Creates a new recipe executor with the given recipe.
    pub fn new(recipe: Recipe<Driver, Os, T>) -> Self {
        Self {
            recipe,
            cache: ImageSymbolCache::new(),
            original_registers: None,
            index: None,
            previous_stack_pointer: None,
        }
    }

    /// Executes the next step in the recipe.
    ///
    /// Returns the new CPU registers after executing the step.
    /// If the recipe has finished executing, returns the original registers.
    pub fn execute(
        &mut self,
        vmi: &VmiContext<Driver, Os>,
    ) -> Result<Option<<<Driver as VmiDriver>::Architecture as Architecture>::Registers>, VmiError>
    {
        // If the stack pointer has decreased, we are likely in a recursive call or APC.
        // In this case, we should not execute the recipe.
        if self.has_stack_pointer_decreased(vmi) {
            return Ok(None);
        }

        let index = match &mut self.index {
            Some(index) => index,
            None => {
                self.original_registers = Some(*vmi.registers());
                self.index.insert(0)
            }
        };

        if let Some(step) = self.recipe.steps.get(*index) {
            tracing::debug!(index, "recipe step");

            let mut registers = *vmi.registers();

            let next = step(&mut RecipeContext {
                vmi,
                registers: &mut registers,
                data: &mut self.recipe.data,
                cache: &mut self.cache,
            })?;

            // Update the stack pointer after executing the step.
            self.previous_stack_pointer = Some(Va(registers.stack_pointer()));

            match next {
                RecipeControlFlow::Continue => {
                    *index += 1;
                    return Ok(Some(registers));
                }
                RecipeControlFlow::Break => {}
                RecipeControlFlow::Repeat => {
                    return Ok(Some(registers));
                }
                RecipeControlFlow::Skip => {
                    *index += 2;
                    return Ok(Some(registers));
                }
                RecipeControlFlow::Goto(i) => {
                    *index = i;
                    return Ok(Some(registers));
                }
            }
        }

        tracing::debug!(
            result = %Hex(vmi.registers().result()),
            "recipe finished"
        );

        self.index = None;
        let original_registers = self.original_registers.expect("original_registers");
        Ok(Some(original_registers))
    }

    /// Returns whether the stack pointer has decreased since the last step.
    ///
    /// This is used to detect irrelevant reentrancy in the recipe,
    /// such as recursive calls, interrupts, or APCs.
    fn has_stack_pointer_decreased(&self, vmi: &VmiContext<Driver, Os>) -> bool {
        let previous_stack_pointer = match self.previous_stack_pointer {
            Some(previous_stack_pointer) => previous_stack_pointer,
            None => return false,
        };

        let current_stack_pointer = Va(vmi.registers().stack_pointer());

        let result = previous_stack_pointer > current_stack_pointer;
        if result {
            tracing::trace!(
                %previous_stack_pointer,
                %current_stack_pointer,
                "stack pointer decreased"
            );
        }

        result
    }

    /// Resets the executor to the initial state.
    pub fn reset(&mut self) {
        self.index = None;
    }

    /// Returns whether the recipe has finished executing.
    pub fn done(&self) -> bool {
        self.index.is_none() && self.original_registers.is_some()
    }
}
