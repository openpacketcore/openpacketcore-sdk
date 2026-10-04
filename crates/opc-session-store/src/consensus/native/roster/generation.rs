//! V4 generation frames carry exact roster/partition endpoint rows and the
//! authenticated last removal. Lifecycle counts preserve transient creation
//! and deletion without making serialized comparison fields authoritative.

use super::super::generation as wire;
use super::super::resident::RowFingerprint;
use super::*;
use std::io::{Read, Write};

fn lifecycle(writer: &mut dyn Write, counts: [u64; 2]) -> io::Result<()> {
    for count in counts {
        writer.write_all(&count.to_le_bytes())?;
    }
    Ok(())
}

fn verify_lifecycle(reader: &mut dyn Read, counts: [u64; 2]) -> io::Result<()> {
    for count in counts {
        wire::expect(reader, &count.to_le_bytes())?;
    }
    Ok(())
}

fn partition(
    writer: &mut dyn Write,
    key: ProductionFloorKey,
    row: Option<&SharedRow<Partition>>,
) -> io::Result<()> {
    writer.write_all(&[u8::from(row.is_some())])?;
    if let Some(row) = row {
        let length = frame::write_partition(&mut io::sink(), key, row)?;
        writer.write_all(&length.to_le_bytes())?;
        if frame::write_partition(writer, key, row)? != length {
            return Err(invalid("native roster generation partition extent changed"));
        }
    }
    Ok(())
}

fn verify_partition(
    reader: &mut dyn Read,
    key: ProductionFloorKey,
    row: Option<&SharedRow<Partition>>,
) -> io::Result<()> {
    wire::expect(reader, &[u8::from(row.is_some())])?;
    if let Some(row) = row {
        let input = wire::read_bytes(reader, frame::MAX_PARTITION)?;
        let (actual, decoded) = frame::read_partition(
            &mut io::Cursor::new(input.bytes()),
            input.bytes().len() as u32,
        )?;
        if actual != key || decoded != **row {
            return Err(invalid(
                "native roster generation partition readback differs",
            ));
        }
    }
    Ok(())
}

fn row(
    writer: &mut dyn Write,
    row: Option<&SharedRow<Row>>,
    root: Option<&RosterAttestationTrustRootV1>,
    scope: &MembershipValidationScope,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    writer.write_all(&[u8::from(row.is_some())])?;
    if let Some(row) = row {
        let root =
            root.ok_or_else(|| invalid("native roster generation configured root absent"))?;
        let length = frame::write_row_detached(&mut io::sink(), row, root, scope, check)?;
        writer.write_all(&length.to_le_bytes())?;
        if frame::write_row_detached(writer, row, root, scope, check)? != length {
            return Err(invalid("native roster generation carrier extent changed"));
        }
    }
    Ok(())
}

fn verify_row(
    reader: &mut wire::PositionedReader<'_>,
    row: Option<&SharedRow<Row>>,
    root: Option<&RosterAttestationTrustRootV1>,
    scope: &MembershipValidationScope,
    check: &impl Fn() -> io::Result<()>,
    relocations: Option<&mut wire::RelocationBuilder>,
) -> io::Result<()> {
    wire::expect(reader, &[u8::from(row.is_some())])?;
    if let Some(row) = row {
        let root =
            root.ok_or_else(|| invalid("native roster generation configured root absent"))?;
        let offset = reader
            .position()
            .checked_add(4)
            .ok_or_else(|| invalid("native roster generation offset overflow"))?;
        let input = wire::read_bytes(reader, frame::MAX_ROW)?;
        let hydrated = frame::read_row(
            &mut io::Cursor::new(input.bytes()),
            input.bytes().len() as u32,
            root,
            scope,
        )?;
        if hydrated.binding() != row.binding()
            || hydrated.projection != *row.projection()
            || hydrated.facts != row.facts()
            || hydrated.reserved_key() != row.reserved_key()
            || !row.matches_canonical(hydrated.canonical())
            || Row::hydration_fingerprint(&hydrated)? != row.row_fingerprint(4, &row.binding())?
        {
            return Err(invalid("native roster generation carrier readback differs"));
        }
        if let Some(relocations) = relocations {
            relocations.roster(row, offset, input.bytes().len() as u32)?;
        }
    }
    check()
}

impl Journal {
    pub(in crate::consensus::native) fn generation_counts(&self) -> [usize; 2] {
        [self.rows.len(), self.partitions.len()]
    }

    pub(in crate::consensus::native) fn write_generation(
        &self,
        writer: &mut dyn Write,
        root: Option<&RosterAttestationTrustRootV1>,
        scope: &MembershipValidationScope,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        for (key, change) in self
            .partitions
            .iter()
            .filter(|(_, change)| change.after.is_none())
            .chain(
                self.partitions
                    .iter()
                    .filter(|(_, change)| change.after.is_some()),
            )
        {
            check()?;
            writer.write_all(&[5])?;
            wire::write_before(writer, change.predecessor_content())?;
            writer.write_all(key.as_bytes())?;
            lifecycle(writer, change.lifecycle())?;
            partition(writer, *key, change.retired.as_ref())?;
            partition(writer, *key, change.after.as_ref())?;
        }
        for (binding, change) in self
            .rows
            .iter()
            .filter(|(_, change)| change.after.is_none())
            .chain(
                self.rows
                    .iter()
                    .filter(|(_, change)| change.after.is_some()),
            )
        {
            check()?;
            writer.write_all(&[6])?;
            wire::write_before(writer, change.predecessor_content())?;
            writer.write_all(&binding.to_bytes())?;
            lifecycle(writer, change.lifecycle())?;
            row(writer, change.retired.as_ref(), root, scope, check)?;
            row(writer, change.after.as_ref(), root, scope, check)?;
        }
        check()
    }

    pub(in crate::consensus::native) fn verify_generation(
        &self,
        reader: &mut wire::PositionedReader<'_>,
        root: Option<&RosterAttestationTrustRootV1>,
        scope: &MembershipValidationScope,
        check: &impl Fn() -> io::Result<()>,
        mut relocations: Option<&mut wire::RelocationBuilder>,
    ) -> io::Result<()> {
        for (key, change) in self
            .partitions
            .iter()
            .filter(|(_, change)| change.after.is_none())
            .chain(
                self.partitions
                    .iter()
                    .filter(|(_, change)| change.after.is_some()),
            )
        {
            check()?;
            wire::expect(reader, &[5])?;
            wire::expect_before(reader, change.predecessor_content())?;
            wire::expect(reader, key.as_bytes())?;
            verify_lifecycle(reader, change.lifecycle())?;
            verify_partition(reader, *key, change.retired.as_ref())?;
            verify_partition(reader, *key, change.after.as_ref())?;
        }
        for (binding, change) in self
            .rows
            .iter()
            .filter(|(_, change)| change.after.is_none())
            .chain(
                self.rows
                    .iter()
                    .filter(|(_, change)| change.after.is_some()),
            )
        {
            check()?;
            wire::expect(reader, &[6])?;
            wire::expect_before(reader, change.predecessor_content())?;
            wire::expect(reader, &binding.to_bytes())?;
            verify_lifecycle(reader, change.lifecycle())?;
            verify_row(reader, change.retired.as_ref(), root, scope, check, None)?;
            verify_row(
                reader,
                change.after.as_ref(),
                root,
                scope,
                check,
                relocations.as_deref_mut(),
            )?;
        }
        check()
    }
}

pub(in crate::consensus::native) fn write_base(
    ledger: &Ledger,
    writer: &mut dyn Write,
    root: Option<&RosterAttestationTrustRootV1>,
    scope: &MembershipValidationScope,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    for (key, value) in &ledger.partitions {
        check()?;
        writer.write_all(&[5])?;
        wire::write_before(writer, None)?;
        writer.write_all(key.as_bytes())?;
        lifecycle(writer, [1, 0])?;
        partition(writer, *key, None)?;
        partition(writer, *key, Some(value))?;
    }
    for (binding, value) in &ledger.rows {
        check()?;
        writer.write_all(&[6])?;
        wire::write_before(writer, None)?;
        writer.write_all(&binding.to_bytes())?;
        lifecycle(writer, [1, 0])?;
        row(writer, None, root, scope, check)?;
        row(writer, Some(value), root, scope, check)?;
    }
    check()
}
