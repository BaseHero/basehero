//! Test-only interruption/append boundary around the real native journal.
use bh_account::journal::*;
use bh_account::storage::DeviceJournal;
use bh_account::{AccountId, Head, VerifiedAccount};
use std::cell::RefCell;

type AdvanceHook = Box<dyn FnMut(&mut DeviceJournal)>;
pub struct HookJournal {
    pub inner: DeviceJournal,
    pub after_advance: AdvanceHook,
    pub pages: RefCell<Vec<(usize, usize)>>,
}
impl AccountJournal for HookJournal {
    fn load(&self) -> Result<Option<JournaledAccount>, JournalError> {
        panic!("native activation must not load lifetime history")
    }
    fn load_projection(&self) -> Result<Option<JournaledProjection>, JournalError> {
        self.inner.load_projection()
    }
    fn advance_projection(&mut self, candidate: &VerifiedAccount) -> Result<(), JournalError> {
        self.inner.advance_projection(candidate)?;
        (self.after_advance)(&mut self.inner);
        Ok(())
    }
    fn has_account(&self) -> Result<bool, JournalError> {
        self.inner.has_account()
    }
    fn history_prefix(
        &self,
        c: Option<HistoryCursor>,
        limit: usize,
    ) -> Result<Option<HistoryPage>, JournalError> {
        assert!((1..=256).contains(&limit));
        let page = self.inner.history_prefix(c, limit)?;
        if let Some(p) = &page {
            let bytes = p.events.iter().map(Vec::len).sum();
            assert!(bytes <= 697344);
            self.pages.borrow_mut().push((p.events.len(), bytes));
        }
        Ok(page)
    }
    fn commit_verified(
        &mut self,
        a: AccountId,
        e: &[&[u8]],
        h: Head,
        s: bool,
    ) -> Result<(), JournalError> {
        self.inner.commit_verified(a, e, h, s)
    }
    fn device(&self) -> Result<Option<JournaledDevice>, JournalError> {
        self.inner.device()
    }
    fn commit_device(&mut self, d: &JournaledDevice) -> Result<(), JournalError> {
        self.inner.commit_device(d)
    }
    fn pending_setup(&self) -> Result<Option<PendingSetupRecord>, JournalError> {
        self.inner.pending_setup()
    }
    fn commit_pending_setup(&mut self, p: &PendingSetupRecord) -> Result<(), JournalError> {
        self.inner.commit_pending_setup(p)
    }
    fn clear_pending_setup(&mut self) -> Result<(), JournalError> {
        self.inner.clear_pending_setup()
    }
    fn staged_admission(&self) -> Result<Option<StagedAdmission>, JournalError> {
        self.inner.staged_admission()
    }
    fn insert_staged_admission(&mut self, s: &StagedAdmission) -> Result<(), JournalError> {
        self.inner.insert_staged_admission(s)
    }
    fn clear_staged_admission(&mut self, s: &StagedAdmission) -> Result<(), JournalError> {
        self.inner.clear_staged_admission(s)
    }
}
