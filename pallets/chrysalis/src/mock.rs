use crate::{self as pallet_chrysalis, Config};
use frame_support::{
	parameter_types,
	traits::{ConstU32, ConstU64, Everything},
};
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage, // Import BuildStorage
};

type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		Balances: pallet_balances,
		Chrysalis: pallet_chrysalis,
	}
);

// FIX: This is the new, complete implementation for frame_system::Config
impl frame_system::Config for Test {
	type BaseCallFilter = Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Nonce = u64; // Was missing
	type Block = Block; // Was missing
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = ConstU64<250>;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = ConstU32<16>;
	type RuntimeTask = (); // Was missing
	type ExtensionsWeightInfo = (); // Was missing
	type SingleBlockMigrations = (); // Was missing
	type MultiBlockMigrator = (); // Was missing
	type PreInherents = (); // Was missing
	type PostInherents = (); // Was missing
	type PostTransactions = (); // Was missing
}

// FIX: This is the new, complete implementation for pallet_balances::Config
impl pallet_balances::Config for Test {
	type Balance = u64;
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ConstU64<1>;
	type AccountStore = System;
	type WeightInfo = ();
	type MaxLocks = ConstU32<50>;
	type MaxReserves = ConstU32<50>;
	type ReserveIdentifier = [u8; 8];
	type RuntimeHoldReason = (); // Was missing
	type RuntimeFreezeReason = (); // Was missing
	type FreezeIdentifier = (); // Was missing
	type MaxFreezes = ConstU32<10>; // Was missing
	type DoneSlashHandler = (); // Was missing
}

parameter_types! {
	pub const TreeDepth: u8 = 2;
	pub const DefaultLeafHash: H256 = H256([0; 32]);
}

impl Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type TreeDepth = TreeDepth;
	type DefaultLeafHash = DefaultLeafHash;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	t.into()
}