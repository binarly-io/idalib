use std::marker::PhantomData;

use crate::ffi::types::{
    idalib_apply_type_by_ordinal, idalib_get_type_ordinal_limit, idalib_is_valid_type_ordinal,
    idalib_tinfo_get_name_by_ordinal,
};
use crate::idb::IDB;
use crate::{Address, IDAError};

pub type TypeIndex = u32;

/// Flags for type application
#[repr(u32)]
pub enum TypeFlags {
    /// This is a guessed type
    GUESSED = 0x0000,
    /// This is a definite type
    DEFINITE = 0x0001,
    /// For delayed function creation
    DELAYFUNC = 0x0002,
    /// Strict type checking
    STRICT = 0x0004,
}

pub struct Type {
    // We'll store the type ordinal instead of the tinfo_t directly
    ordinal: TypeIndex,
}

impl Type {
    pub(crate) fn from_ordinal(ordinal: TypeIndex) -> Self {
        Self { ordinal }
    }

    pub fn name(&self) -> Option<String> {
        let name = unsafe { idalib_tinfo_get_name_by_ordinal(self.ordinal) }.ok()?;
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Apply this type to an address with default flags (TINFO_DEFINITE)
    pub fn apply_to_address(&self, address: Address) -> Result<(), IDAError> {
        self.apply_to_address_with_flags(address, TypeFlags::DEFINITE)
    }

    /// Apply this type to an address with specific flags
    pub fn apply_to_address_with_flags(
        &self,
        address: Address,
        flags: TypeFlags,
    ) -> Result<(), IDAError> {
        let success =
            unsafe { idalib_apply_type_by_ordinal(address.into(), self.ordinal, flags as u32) };
        if success {
            Ok(())
        } else {
            Err(IDAError::ffi_with("Failed to apply type to address"))
        }
    }

    /// Get the ordinal (index) of this type
    pub fn ordinal(&self) -> TypeIndex {
        self.ordinal
    }
}

pub struct TypeList<'a> {
    _marker: PhantomData<&'a IDB>,
}

impl<'a> TypeList<'a> {
    pub(crate) fn new(_: &'a IDB) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn get_by_index(&self, index: TypeIndex) -> Option<Type> {
        if index == 0 {
            return None; // Ordinals start at 1
        }

        let is_valid = unsafe { idalib_is_valid_type_ordinal(index) };
        if !is_valid {
            return None;
        }

        Some(Type::from_ordinal(index))
    }

    pub fn len(&self) -> usize {
        let limit = unsafe { idalib_get_type_ordinal_limit() };
        if limit == 0 || limit == u32::MAX {
            0
        } else {
            (limit - 1) as usize // Ordinals start at 1, so count is limit - 1
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> TypeListIter<'_, 'a> {
        TypeListIter {
            type_list: self,
            current_ordinal: 1, // Start at 1, not 0
            max_ordinal: unsafe { idalib_get_type_ordinal_limit() },
        }
    }
}

pub struct TypeListIter<'s, 'a> {
    type_list: &'s TypeList<'a>,
    current_ordinal: u32,
    max_ordinal: u32,
}

impl<'s, 'a> Iterator for TypeListIter<'s, 'a> {
    type Item = (TypeIndex, Type);

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_ordinal < self.max_ordinal {
            let ordinal = self.current_ordinal;
            self.current_ordinal += 1;

            if let Some(typ) = self.type_list.get_by_index(ordinal) {
                return Some((ordinal, typ));
            }
        }

        None
    }
}
