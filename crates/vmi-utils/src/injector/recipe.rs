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

    /// Whether the bridge support is enabled.
    pub(super) bridge: bool,
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
            bridge: false,
        }
    }

    /// Creates a new recipe with the given data and bridge support.
    pub fn new_with_bridge(data: T) -> Self {
        Self {
            steps: Vec::new(),
            data,
            bridge: true,
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
        }
    }

    /// Executes the next step in the recipe.
    pub fn execute(
        &mut self,
        vmi: &VmiContext<Driver, Os>,
    ) -> Result<<<Driver as VmiDriver>::Architecture as Architecture>::Registers, VmiError> {
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

            match next {
                RecipeControlFlow::Continue => {
                    *index += 1;
                    return Ok(registers);
                }
                RecipeControlFlow::Break => {}
                RecipeControlFlow::Repeat => {
                    return Ok(registers);
                }
                RecipeControlFlow::Skip => {
                    *index += 2;
                    return Ok(registers);
                }
                RecipeControlFlow::Goto(i) => {
                    *index = i;
                    return Ok(registers);
                }
            }
        }

        tracing::debug!(
            result = %Hex(vmi.registers().result()),
            "recipe finished"
        );

        self.index = None;
        let original_registers = self.original_registers.expect("original_registers");
        Ok(original_registers)
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
