use elliptic_curve::{group::GroupEncoding, Group};

/// A convenience trait for group types.
pub trait GroupType: Group + GroupEncoding + Default {}

impl<G: Group + GroupType + Default> GroupType for G {}
