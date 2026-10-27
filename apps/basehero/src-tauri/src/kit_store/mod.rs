use crate::error::CommandError;
use bh_core::{Account, AccountId};
use std::sync::Arc;
use zeroize::Zeroizing;

#[cfg(target_os = "android")]
mod android;

pub trait Store: Send + Sync {
    fn enabled(&self) -> bool {
        true
    }
    fn save(&self, account: AccountId, kit: &str) -> Result<(), CommandError>;
    fn load(&self, account: AccountId) -> Result<Option<Zeroizing<String>>, CommandError>;
    fn delete(&self, account: AccountId) -> Result<(), CommandError>;
}

pub struct NativeStore;
impl Store for NativeStore {
    fn enabled(&self) -> bool {
        cfg!(target_os = "android")
    }
    fn save(&self, account: AccountId, kit: &str) -> Result<(), CommandError> {
        #[cfg(target_os = "android")]
        android::save(&account.to_string(), kit)?;
        #[cfg(not(target_os = "android"))]
        let _ = (account, kit);
        Ok(())
    }
    fn load(&self, account: AccountId) -> Result<Option<Zeroizing<String>>, CommandError> {
        #[cfg(target_os = "android")]
        return android::load(&account.to_string());
        #[cfg(not(target_os = "android"))]
        {
            let _ = account;
            Ok(None)
        }
    }
    fn delete(&self, account: AccountId) -> Result<(), CommandError> {
        #[cfg(target_os = "android")]
        android::delete(&account.to_string())?;
        #[cfg(not(target_os = "android"))]
        let _ = account;
        Ok(())
    }
}

pub async fn load(
    store: Arc<dyn Store>,
    id: AccountId,
) -> Result<Option<Zeroizing<String>>, CommandError> {
    tokio::task::spawn_blocking(move || store.load(id))
        .await
        .map_err(|_| unavailable())?
}
pub async fn delete(store: Arc<dyn Store>, id: AccountId) -> Result<(), CommandError> {
    tokio::task::spawn_blocking(move || store.delete(id))
        .await
        .map_err(|_| unavailable())?
}
pub async fn save_account(store: Arc<dyn Store>, account: Account) -> Result<(), CommandError> {
    let Some(kit) = account.recovery_kit()? else {
        return Ok(());
    };
    let id = account.id();
    let value = Zeroizing::new(kit.display());
    tokio::task::spawn_blocking(move || {
        if store.load(id)?.as_ref().map(|s| s.as_str()) != Some(value.as_str()) {
            store.save(id, &value)?;
        }
        Ok::<_, CommandError>(())
    })
    .await
    .map_err(|_| unavailable())??;
    // Local Block Store is not a backup against losing this phone; only the
    // person's own confirmation marks the recovery kit saved.
    Ok(())
}
fn unavailable() -> CommandError {
    CommandError {
        kind: "Storage".into(),
        message: "Google kit storage unavailable".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake(Mutex<HashMap<AccountId, String>>);
    impl Store for Fake {
        fn save(&self, account: AccountId, kit: &str) -> Result<(), CommandError> {
            self.0.lock().unwrap().insert(account, kit.to_string());
            Ok(())
        }
        fn load(&self, account: AccountId) -> Result<Option<Zeroizing<String>>, CommandError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(&account)
                .cloned()
                .map(Zeroizing::new))
        }
        fn delete(&self, account: AccountId) -> Result<(), CommandError> {
            self.0.lock().unwrap().remove(&account);
            Ok(())
        }
    }
    #[tokio::test]
    async fn kit_store_save_load_replace_delete() {
        let store: Arc<dyn Store> = Arc::new(Fake::default());
        let id = AccountId::random();
        assert!(load(store.clone(), id).await.unwrap().is_none());
        store.save(id, "first").unwrap();
        assert_eq!(
            load(store.clone(), id)
                .await
                .unwrap()
                .as_ref()
                .map(|s| s.as_str()),
            Some("first")
        );
        store.save(id, "second").unwrap();
        assert_eq!(
            load(store.clone(), id)
                .await
                .unwrap()
                .as_ref()
                .map(|s| s.as_str()),
            Some("second")
        );
        delete(store.clone(), id).await.unwrap();
        assert!(load(store, id).await.unwrap().is_none());
    }
}
