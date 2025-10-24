use crate::{self as pallet_chrysalis, Config};
use frame_support::{
	parameter_types,
	traits::{ConstU32, ConstU64, Everything},
	traits::tokens::currency::ReservableCurrency, // FIX: Added ReservableCurrency
};
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage,
};
use frame_support::PalletId;

type Block = frame_system::mocking::MockBlock<Test>;
// FIX: Mock Balance type, needed for the new Balance generic constraint
pub type Balance = u64; 

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		Balances: pallet_balances,
		Chrysalis: pallet_chrysalis,
	}
);

impl frame_system::Config for Test {
	type BaseCallFilter = Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Nonce = u64;
	type Block = Block;
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
	type RuntimeTask = ();
	type ExtensionsWeightInfo = ();
	type SingleBlockMigrations = ();
	type MultiBlockMigrator = ();
	type PreInherents = ();
	type PostInherents = ();
	type PostTransactions = ();
}

impl pallet_balances::Config for Test {
	// FIX: Use the mock Balance type
	type Balance = Balance; 
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ConstU64<1>;
	type AccountStore = System;
	type WeightInfo = ();
	type MaxLocks = ConstU32<50>;
	type MaxReserves = ConstU32<50>;
	type ReserveIdentifier = [u8; 8];
	type RuntimeHoldReason = ();
	type RuntimeFreezeReason = ();
	type FreezeIdentifier = ();
	type MaxFreezes = ConstU32<10>;
	type DoneSlashHandler = ();
}

parameter_types! {
	pub const TreeDepth: u8 = 2;
	pub const DefaultLeafHash: H256 = H256([0; 32]);
	pub const ChrysalisPalletId: PalletId = PalletId(*b"py/chrys");
}

impl Config for Test {
	type TreeDepth = TreeDepth;
	type DefaultLeafHash = DefaultLeafHash;
	// FIX: Implement Currency and Balance for the Pallet Config
	type Currency = Balances; 
	type Balance = Balance; 
	type PalletId=ChrysalisPalletId;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	t.into()
}
