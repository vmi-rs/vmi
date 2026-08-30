//! Msgbox shellcode recipe: displays a message box in a Windows guest process.

mod bridge;
mod parameters;
mod recipe;

pub use self::{bridge::MsgboxBridge, parameters::MsgboxParameters, recipe::msgbox_recipe};
