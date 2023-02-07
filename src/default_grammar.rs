//! The grammar_mut.rs file is supposed to be generated dynamically by `fzero`. If the user does not
//! want to do grammar-fuzzing, `grammar_mut.rs` is never generated, so this acts as a placeholder.
//! It supports the bare minimum api's to compile with the project, but will panic if an attempt is
//! made to actually use this
//! If you want the real `grammar_mut.rs` file to be generated, set `GRAMMAR` to true in the 
//! makefile and specify a Grammar file in json format for it to consume.

#![allow(unreachable_code)]

pub struct GrammarMut {}
impl GrammarMut {
    pub fn default() -> Self {
        Self{}
    }

    pub fn generate_input(&mut self) -> Vec<u8> {
        panic!("Attempting to use grammar_mut without having first generated it");
        Vec::new()
    }
}
