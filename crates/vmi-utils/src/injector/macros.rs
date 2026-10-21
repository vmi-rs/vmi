#[doc(hidden)]
pub mod __private {
    pub mod vmi_core {
        pub use vmi_core::*;
    }

    pub mod zerocopy {
        pub use zerocopy::*;
    }

    use vmi_core::{Va, VmiError, VmiState, os::VmiOsImage as _};

    use super::super::{
        OsAdapter,
        recipe::{RecipeContext, SymbolCache},
    };

    /// Finds the image that `inject!` names and retrieves its exported
    /// symbols. Returns map of exported symbols and their virtual addresses,
    /// or `Ok(None)` when no image matches.
    pub fn exported_symbols<Os>(
        vmi: &VmiState<'_, Os>,
        name: &str,
    ) -> Result<Option<SymbolCache>, VmiError>
    where
        Os: OsAdapter,
    {
        let image_base = match Os::find_image(vmi, name)? {
            Some(image_base) => image_base,
            None => return Ok(None),
        };

        let image = vmi.os().image(image_base)?;
        let symbols = image.exports()?;

        tracing::trace!(
            va = %image_base,
            symbols = symbols.len(),
            "image found"
        );

        Ok(Some(
            symbols
                .into_iter()
                .map(|symbol| (symbol.name, symbol.address))
                .collect(),
        ))
    }

    /// Looks up a symbol in the function cache. If the symbol is not found, it
    /// retrieves the exported symbols from the image that `name` names and
    /// caches them. Returns virtual address of the symbol if found.
    #[tracing::instrument(skip(ctx), err)]
    pub fn lookup_symbol<Os, T>(
        ctx: &mut RecipeContext<'_, Os, T>,
        name: &str,
        symbol: &str,
    ) -> Result<Option<Va>, VmiError>
    where
        Os: OsAdapter,
    {
        use std::collections::hash_map::Entry;

        match ctx.cache.entry(name.to_owned()) {
            Entry::Occupied(entry) => match entry.into_mut().get(symbol).copied() {
                Some(va) => {
                    tracing::trace!(cache_hit = true, %va, "symbol found");
                    Ok(Some(va))
                }
                None => {
                    tracing::error!(cache_hit = true, "symbol not found");
                    Ok(None)
                }
            },
            Entry::Vacant(entry) => {
                let symbols = match exported_symbols(ctx.vmi, name)? {
                    Some(symbols) => symbols,
                    None => {
                        tracing::error!(cache_hit = false, "image not found");
                        return Ok(None);
                    }
                };

                let va = match symbols.get(symbol).copied() {
                    Some(va) => va,
                    None => {
                        tracing::error!(cache_hit = false, "symbol not found");
                        return Ok(None);
                    }
                };

                tracing::trace!(cache_hit = false, %va, "symbol found");

                entry.insert(symbols);
                Ok(Some(va))
            }
        }
    }
}

/// A macro for defining a recipe.
///
/// The recipe is a series of steps that are executed in order.
/// Each step is a closure that takes a [`RecipeContext`] as an argument.
/// The `RecipeContext` contains the VMI context, the recipe data, and the symbol cache.
/// The recipe data is a user-defined struct that is passed to each step.
///
/// # Macro Syntax
///
/// The macro accepts:
/// - An initial recipe created with `Recipe::new()`
/// - One or more step blocks containing injection code
///
/// Within step blocks, the following helpers are available:
/// - `vmi!()` - Access the VMI context
/// - `registers!()` - Access the registers
/// - `data!()` - Access recipe data
/// - `inject!()` - Inject and call functions
/// - `copy_to_stack!()` - Copy data to the stack
///
/// [`RecipeContext`]: super::RecipeContext
#[doc(hidden)]
#[macro_export]
macro_rules! _private_recipe {
    [
        $recipe:expr,
        $( { $($step:tt)* } ),* $(,)?
    ] => {
        $recipe
        $(
             .step($crate::_private_recipe! { @step $($step)* })
        )*
    };

    (@expand $($body:tt)*) => {
        macro_rules! __with_dollar_sign { $($body)* }
        __with_dollar_sign!($);
    };

    (@step $($body:tt)*) => {
        move |ctx| {

            //
            // The `ctx` variable is a `RecipeContext` struct, which is hidden
            // from the user.
            // However, user might want to interact with its fields, such as `vmi`
            // and `data`. To make this possible, we define a few macros that will
            // be injected into the recipe's closure. These macros will allow the
            // user to access these fields.
            //

            $crate::_private_recipe! { @expand
                ($d:tt) => {
                    /// Access the `vmi` field of the `RecipeContext`.
                    #[allow(unused_macros)]
                    macro_rules! vmi {
                        () => {
                            ctx.vmi
                        };
                    }

                    /// Access the `registers` field of the `RecipeContext`.
                    #[allow(unused_macros)]
                    macro_rules! registers {
                        () => {
                            ctx.registers
                        };
                    }

                    /// Access the `data` field of the `RecipeContext`.
                    #[allow(unused_macros)]
                    macro_rules! data {
                        ($d($d name:tt)*) => {
                            ctx.data.$d($d name)*
                        };
                    }

                    /// Inject a function call into the recipe.
                    ///
                    /// This macro creates a [`CallBuilder`], places the arguments
                    /// on the stack if needed, and sets up the registers (including
                    /// the instruction pointer) for the function call.
                    ///
                    /// Returns [`RecipeControlFlow::Continue`] if the function call
                    /// was successfully prepared.
                    ///
                    /// # Warning
                    ///
                    /// This macro doesn't verify if the function is called correctly.
                    /// It is the user's responsibility to ensure that the function
                    /// is called with the correct number and types of arguments.
                    ///
                    /// # Examples
                    ///
                    /// ```compile_fail
                    /// inject! {
                    ///     user32!MessageBoxA(
                    ///         0,                          // hWnd
                    ///         data![text],                // lpText
                    ///         data![caption],             // lpCaption
                    ///         0                           // uType
                    ///     )
                    /// }
                    /// ```
                    #[allow(unused_macros)]
                    macro_rules! inject {
                        ($image:ident!$function:ident($d($d arg:expr),*)) => {
                            $crate::_private_recipe!(@inject ctx, $image!$function($d($d arg),*))
                        };

                        ($image:literal!$function:ident($d($d arg:expr),*)) => {
                            $crate::_private_recipe!(@inject ctx, $image!$function($d($d arg),*))
                        };

                        ($function:ident($d($d arg:expr),*)) => {
                            $crate::_private_recipe!(@inject ctx, $function($d($d arg),*))
                        };
                    }

                    /// Copy data to the stack.
                    ///
                    /// This macro is used to copy data to the stack in preparation
                    /// for a function call.
                    ///
                    /// Returns the guest virtual address of the copied data on the stack.
                    ///
                    /// # Examples
                    ///
                    /// ```compile_fail
                    /// // Allocate a value on the stack to store the output parameter.
                    /// data![bytes_written_ptr] = copy_to_stack!(0u64)?;
                    ///
                    /// inject! {
                    ///     kernel32!WriteFile(
                    ///         data![handle],              // hFile
                    ///         data![content],             // lpBuffer
                    ///         data![content].len(),       // nNumberOfBytesToWrite
                    ///         data![bytes_written_ptr],   // lpNumberOfBytesWritten
                    ///         0                           // lpOverlapped
                    ///     )
                    /// }
                    /// ```
                    #[allow(unused_macros)]
                    macro_rules! copy_to_stack {
                        ($d($d name:tt)*) => {{
                            use $crate::injector::{
                                macros::__private::{
                                    vmi_core::{Architecture, Va, VmiError, VmiState},
                                    zerocopy::{Immutable, IntoBytes},
                                },
                                ArchAdapter, OsAdapter,
                            };

                            fn __copy_to_stack<Os, T>(
                                vmi: &VmiState<'_, Os>,
                                registers: &mut <Os::Architecture as Architecture>::Registers,
                                data: T,
                            ) -> Result<Va, VmiError>
                            where
                                Os: OsAdapter,
                                Os::Architecture: ArchAdapter<Os::Driver>,
                                T: IntoBytes + Immutable,
                            {
                                vmi.underlying_os().copy_to_stack(
                                    vmi,
                                    registers,
                                    data.as_bytes(),
                                    align_of::<T>(),
                                )
                            }

                            __copy_to_stack(vmi!(), registers!(), $d($d name)*)
                        }};
                    }
                }
            }

            //
            // After the macros are defined, we can now expand the recipe step.
            //

            $($body)*
        }
    };

    (@inject $ctx:expr, $image:ident!$function:ident($($arg:expr),*)) => {
        $crate::_private_recipe!(@lookup $ctx, stringify!($image), $function($($arg),*))
    };

    (@inject $ctx:expr, $image:literal!$function:ident($($arg:expr),*)) => {
        $crate::_private_recipe!(@lookup $ctx, $image, $function($($arg),*))
    };

    (@lookup $ctx:expr, $image:expr, $function:ident($($arg:expr),*)) => {
        'm: {
            use $crate::injector::macros::__private::{self, vmi_core::VmiError};

            //
            // The parent macro can be invoked as follows:
            // ```
            // inject! {
            //     kernel32!VirtualAlloc(
            //         0,                          // lpAddress
            //         0x1000,                     // dwSize
            //         MEM_COMMIT | MEM_RESERVE,   // flAllocationType
            //         PAGE_EXECUTE_READWRITE      // flProtect
            //     )
            // }
            // ```
            // In this case, the `$image` is `kernel32`, the `$function` is `VirtualAlloc`,
            // and the `$($arg),*` are the arguments to the function.
            //
            // `OsAdapter::find_image` turns the `$image` into an image, such as
            // `kernel32.dll` on Windows, and the symbol address comes from its
            // exports.
            //
            // Note that the lookup can return a [`VmiError::PageFault`].
            //

            let function = match __private::lookup_symbol($ctx, $image, stringify!($function)) {
                Ok(Some(function)) => function,
                Ok(None) => break 'm Err(VmiError::Other(concat!(stringify!($function), " not found"))),
                Err(err) => break 'm Err(err),
            };

            tracing::trace!(
                function = stringify!($function),
                $(arg = ?$arg,)*
                "preparing function call"
            );

            $crate::_private_recipe!(@inject $ctx, function($($arg),*))
        }
    };


    (@inject $ctx:expr, $function:ident($($arg:expr),*)) => {
        'm: {
            use $crate::injector::{CallBuilder, OsAdapter as _, RecipeControlFlow};

            let call = CallBuilder::new($function)
                $(.with_argument(&$arg))*;

            if let Err(err) = $ctx.vmi.underlying_os().prepare_function_call($ctx.vmi, $ctx.registers, call) {
                break 'm Err(err);
            }

            Ok(RecipeControlFlow::Continue)
        }
    };
}
