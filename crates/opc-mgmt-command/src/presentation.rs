use crate::{HelpText, SchemaPath};

/// One table column backed by a typed result field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnSpec {
    heading: HelpText,
    field: SchemaPath,
}

impl ColumnSpec {
    /// Constructs a table column.
    #[must_use]
    pub fn new(heading: HelpText, field: SchemaPath) -> Self {
        Self { heading, field }
    }

    /// Human heading.
    pub fn heading(&self) -> &HelpText {
        &self.heading
    }

    /// Typed result field.
    pub fn field(&self) -> &SchemaPath {
        &self.field
    }
}

/// Structured tabular presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSpec {
    columns: Vec<ColumnSpec>,
}

impl TableSpec {
    /// Constructs a table. Freeze rejects an empty/oversized column list.
    #[must_use]
    pub fn new(columns: impl IntoIterator<Item = ColumnSpec>) -> Self {
        Self {
            columns: columns.into_iter().collect(),
        }
    }

    /// Columns in display order.
    pub fn columns(&self) -> &[ColumnSpec] {
        &self.columns
    }
}

/// Ordered detail fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailSpec {
    fields: Vec<SchemaPath>,
}

impl DetailSpec {
    /// Constructs a detail view.
    #[must_use]
    pub fn new(fields: impl IntoIterator<Item = SchemaPath>) -> Self {
        Self {
            fields: fields.into_iter().collect(),
        }
    }

    /// Result fields in display order.
    pub fn fields(&self) -> &[SchemaPath] {
        &self.fields
    }
}

/// Hierarchical tree presentation rooted at one result field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeSpec {
    root: SchemaPath,
}

impl TreeSpec {
    /// Constructs a tree view.
    #[must_use]
    pub fn new(root: SchemaPath) -> Self {
        Self { root }
    }

    /// Root field.
    pub fn root(&self) -> &SchemaPath {
        &self.root
    }
}

/// Streaming event presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventStreamSpec {
    fields: Vec<SchemaPath>,
}

impl EventStreamSpec {
    /// Constructs an event stream view.
    #[must_use]
    pub fn new(fields: impl IntoIterator<Item = SchemaPath>) -> Self {
        Self {
            fields: fields.into_iter().collect(),
        }
    }

    /// Fields in display order.
    pub fn fields(&self) -> &[SchemaPath] {
        &self.fields
    }
}

/// Scalar presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalarSpec {
    field: SchemaPath,
}

impl ScalarSpec {
    /// Constructs a scalar view.
    #[must_use]
    pub fn new(field: SchemaPath) -> Self {
        Self { field }
    }

    /// Result field.
    pub fn field(&self) -> &SchemaPath {
        &self.field
    }
}

/// Declarative result presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationSpec {
    /// Table.
    Table(TableSpec),
    /// Detail fields.
    Detail(DetailSpec),
    /// Hierarchical tree.
    Tree(TreeSpec),
    /// Event stream.
    EventStream(EventStreamSpec),
    /// One scalar value.
    Scalar(ScalarSpec),
}

impl PresentationSpec {
    pub(crate) fn fields(&self) -> Box<dyn Iterator<Item = &SchemaPath> + '_> {
        match self {
            Self::Table(table) => Box::new(table.columns().iter().map(ColumnSpec::field)),
            Self::Detail(detail) => Box::new(detail.fields().iter()),
            Self::Tree(tree) => Box::new(std::iter::once(tree.root())),
            Self::EventStream(stream) => Box::new(stream.fields().iter()),
            Self::Scalar(scalar) => Box::new(std::iter::once(scalar.field())),
        }
    }

    pub(crate) fn item_count(&self) -> usize {
        match self {
            Self::Table(table) => table.columns().len(),
            Self::Detail(detail) => detail.fields().len(),
            Self::Tree(_) | Self::Scalar(_) => 1,
            Self::EventStream(stream) => stream.fields().len(),
        }
    }

    pub(crate) fn text_bytes(&self) -> usize {
        match self {
            Self::Table(table) => table
                .columns()
                .iter()
                .map(|column| column.heading().as_str().len() + column.field().as_str().len())
                .sum(),
            _ => self.fields().map(|field| field.as_str().len()).sum(),
        }
    }
}
