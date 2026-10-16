//! The login-route generic-password items, exactly as the app stored them
//! before the helper: class, service, account and data only.
use bh_mac_keychain_helper::{Item, Store};
use core_foundation::data::CFData;
use security_framework::{
    item::{
        ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit, Location, SearchResult,
    },
    os::macos::keychain::{KeychainUserInteractionLock, SecKeychain},
};
use std::path::Path;
use zeroize::Zeroizing;

const NOT_FOUND: i32 = -25300; // errSecItemNotFound

pub struct Keychain {
    prefix: &'static str,
    // A pinned keychain file and the prompt suppression that goes with it.
    file: Option<(SecKeychain, KeychainUserInteractionLock)>,
}

impl Keychain {
    pub fn open(prefix: &'static str, file: Option<&Path>) -> Result<Self, i32> {
        let file = match file {
            None => None,
            Some(path) => {
                let keychain = SecKeychain::open(path).map_err(|e| e.code())?;
                let quiet = SecKeychain::disable_user_interaction().map_err(|e| e.code())?;
                Some((keychain, quiet))
            }
        };
        Ok(Self { prefix, file })
    }

    fn service(&self, item: Item) -> String {
        format!("{}{}", self.prefix, item.service_suffix())
    }

    fn query(&self, item: Item) -> ItemSearchOptions {
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::generic_password())
            .service(&self.service(item))
            .account(&item.account());
        if let Some((keychain, _)) = &self.file {
            query.keychains(std::slice::from_ref(keychain));
        }
        query
    }
}

impl Store for Keychain {
    fn read(&mut self, item: Item) -> Result<Zeroizing<Vec<u8>>, i32> {
        let mut query = self.query(item);
        query.load_data(true).limit(Limit::Max(1));
        let mut results = query.search().map_err(|e| e.code())?;
        match results.pop() {
            Some(SearchResult::Data(data)) if results.is_empty() => Ok(Zeroizing::new(data)),
            None => Err(NOT_FOUND),
            Some(_) => Err(-1),
        }
    }

    fn add(&mut self, item: Item, value: &[u8]) -> Result<(), i32> {
        let mut add = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(value),
        });
        add.set_service(self.service(item))
            .set_account_name(item.account());
        if let Some((keychain, _)) = &self.file {
            add.set_location(Location::FileKeychain(keychain.clone()));
        }
        // SecItemAdd fails on a duplicate; nothing here updates an existing item.
        add.add().map_err(|e| e.code())
    }

    fn delete(&mut self, item: Item) -> Result<(), i32> {
        self.query(item).delete().map_err(|e| e.code())
    }
}
