pub mod config;
pub mod event;
pub mod filter;
pub mod sink;
pub mod source;

pub use config::Config;
pub use event::{NormalizedEvent, Severity, SlackActor, SlackContext, SlackEntity, SlackPayload, SourceTag};
pub use filter::{FilterEngine, FilterRule, MatchOp};
pub use sink::WazuhSink;
pub use source::{LogSource, SourceKind};
