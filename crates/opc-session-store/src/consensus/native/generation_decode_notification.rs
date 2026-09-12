//! Full selected notification decoding with caller-owned input and scratch.
//! Preparation admits allocation only; every typed field and full fingerprint
//! is checked by the same decoder as the original serial read.

use super::*;

pub(in crate::consensus::native) fn notification_encoding_bytes(
    entry: &ReplicationEntry,
) -> io::Result<usize> {
    changes::notification_payload(entry)?
        .checked_mul(12)
        .and_then(|bytes| bytes.checked_add(METADATA))
        .ok_or_else(|| invalid("native snapshot notification encoding reservation overflow"))
}

pub(in crate::consensus::native) struct NotificationInput {
    input: resident::SelectedBytes,
    expected: facts::Row<facts::Notification>,
    scratch: usize,
    encoding: usize,
}

impl NotificationInput {
    pub(in crate::consensus::native) fn new(
        input: resident::SelectedBytes,
        expected: facts::Row<facts::Notification>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        let scratch = notification_scratch(input.bytes())?;
        // The original borrowed preflight charges six times the complete
        // payload sum plus METADATA. Admit the original twelve-times-sum JSON
        // charge too, before a batch can retain any independent decoded row.
        let encoding = scratch
            .checked_sub(METADATA)
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(METADATA))
            .ok_or_else(|| invalid("native notification export encoding charge overflows"))?;
        Ok(Self {
            input,
            expected,
            scratch,
            encoding,
        })
    }

    pub(in crate::consensus::native) fn charged_bytes(&self) -> io::Result<usize> {
        self.input
            .bytes()
            .len()
            .checked_add(self.scratch)
            .and_then(|bytes| bytes.checked_add(self.encoding))
            .ok_or_else(|| invalid("native notification export row charge overflows"))
    }

    pub(in crate::consensus::native) fn reserve_small(
        self,
        reserve: &impl Fn(usize) -> io::Result<VerificationMemory>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<NotificationPreparation> {
        check()?;
        let Ok(memory) = reserve(self.scratch) else {
            return Ok(NotificationPreparation::Serial(self));
        };
        let Ok(encoding_memory) = reserve(self.encoding) else {
            return Ok(NotificationPreparation::Serial(self));
        };
        check()?;
        Ok(NotificationPreparation::Ready(PreparedNotification {
            input: self,
            memory,
            encoding_memory,
        }))
    }

    pub(in crate::consensus::native) fn decode_serial(
        self,
        frontiers: &NativeFrontiers,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<ExportNotification> {
        let row = owned_notification(self.input.bytes(), self.expected, frontiers, check)?;
        // Match NativeNotification::read: selected bytes drop before the
        // original independent JSON output reservation is requested.
        drop(self.input);
        let encoding_memory =
            VerificationMemory::reserve(notification_encoding_bytes(row.entry())?)?;
        Ok(ExportNotification {
            row,
            _encoding_memory: encoding_memory,
        })
    }
}

pub(in crate::consensus::native) enum NotificationPreparation {
    Ready(PreparedNotification),
    Serial(NotificationInput),
}

pub(in crate::consensus::native) struct PreparedNotification {
    input: NotificationInput,
    memory: VerificationMemory,
    encoding_memory: VerificationMemory,
}

impl PreparedNotification {
    pub(in crate::consensus::native) fn decode(
        self,
        frontiers: &NativeFrontiers,
    ) -> io::Result<ExportNotification> {
        let entry =
            decode_owned_notification(self.input.input.bytes(), self.input.expected, frontiers)?;
        if notification_encoding_bytes(&entry)? != self.input.encoding {
            return Err(invalid("native notification export payload charge differs"));
        }
        Ok(ExportNotification {
            row: OwnedNotification {
                entry,
                _memory: self.memory,
            },
            _encoding_memory: self.encoding_memory,
        })
    }
}

pub(in crate::consensus::native) struct ExportNotification {
    row: OwnedNotification,
    // The full original encoding charge survives until caller-side SQL output
    // completes. Decoded rows drop before either reservation is refunded.
    _encoding_memory: VerificationMemory,
}

impl ExportNotification {
    pub(in crate::consensus::native) fn entry(&self) -> &ReplicationEntry {
        self.row.entry()
    }
}
