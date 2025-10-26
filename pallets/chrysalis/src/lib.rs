#![cfg_attr(not(feature = "std"), no_std)]

// This must be at the top of the file.
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	// --- Substrate Imports ---
	use frame_support::{
		pallet_prelude::{Decode, *},
		traits::{Currency, ExistenceRequirement, ReservableCurrency}, PalletId,
	};
	use frame_system::pallet_prelude::*;
	use sp_std::vec; // Use sp_std::vec for no_std
	use sp_std::vec::Vec;
	
	use core::str::FromStr; // For parsing constants
	use hex; // For parsing constants
    use sp_runtime::traits::{
        AccountIdConversion, AtLeast32BitUnsigned, Member, MaybeSerializeDeserialize, CheckedSub
    };

	// --- Arkworks Imports ---
	use ark_bls12_381::{Bls12_381, Fr};
	use ark_ff::{BigInteger, PrimeField, Zero,One};
	use ark_groth16::{Groth16, Proof, VerifyingKey};
	use ark_serialize::CanonicalDeserialize;
	use ark_snark::SNARK;
	use ark_sponge::{poseidon::{PoseidonConfig, PoseidonSponge}, CryptographicSponge};// --- END Arkworks Imports ---
	#[pallet::pallet]
	pub struct Pallet<T>(_);

	// --- PASTE YOUR VERIFYING KEY BYTES HERE ---
	pub const VERIFYING_KEY: &[u8] = &[3, 82, 163, 29, 219, 4, 13, 164, 81, 154, 133, 140, 26, 140, 149, 70, 239, 171, 102, 9, 61, 187, 54, 115, 131, 116, 49, 40, 23, 19, 182, 41, 54, 9, 96, 158, 19, 152, 119, 98, 145, 18, 131, 143, 188, 237, 108, 107, 18, 14, 214, 52, 26, 84, 46, 16, 67, 88, 168, 114, 189, 40, 235, 74, 221, 77, 21, 195, 44, 86, 212, 101, 12, 19, 65, 105, 118, 26, 216, 112, 116, 238, 214, 158, 41, 178, 160, 45, 151, 8, 247, 136, 7, 38, 231, 39, 18, 109, 234, 181, 177, 63, 57, 200, 224, 94, 167, 81, 142, 1, 145, 44, 111, 168, 69, 79, 131, 227, 105, 186, 128, 249, 21, 138, 165, 183, 152, 202, 27, 38, 43, 63, 227, 249, 205, 187, 121, 248, 176, 49, 139, 249, 126, 131, 23, 28, 181, 232, 40, 17, 74, 85, 149, 193, 70, 246, 72, 85, 59, 212, 100, 57, 245, 120, 62, 33, 23, 169, 88, 133, 55, 209, 66, 165, 202, 225, 79, 153, 63, 73, 185, 238, 48, 164, 147, 42, 31, 169, 143, 15, 58, 49, 10, 161, 29, 35, 115, 166, 254, 150, 24, 68, 229, 97, 176, 239, 79, 67, 6, 182, 212, 106, 23, 93, 26, 213, 253, 16, 121, 17, 10, 40, 134, 18, 148, 101, 160, 179, 20, 66, 94, 153, 131, 10, 7, 26, 120, 239, 192, 165, 3, 78, 131, 160, 220, 240, 46, 8, 20, 53, 29, 1, 229, 58, 77, 190, 239, 161, 162, 112, 123, 163, 102, 188, 226, 52, 151, 185, 124, 109, 59, 68, 7, 89, 84, 128, 237, 5, 162, 162, 74, 134, 44, 136, 99, 197, 67, 85, 8, 111, 1, 244, 128, 211, 52, 104, 167, 100, 11, 89, 229, 138, 53, 196, 247, 38, 78, 125, 162, 247, 234, 234, 80, 46, 103, 132, 173, 115, 167, 25, 132, 178, 248, 46, 247, 68, 92, 220, 24, 135, 42, 43, 235, 24, 83, 90, 23, 123, 249, 48, 190, 156, 184, 125, 137, 85, 171, 35, 179, 206, 162, 133, 67, 53, 222, 175, 30, 71, 235, 151, 78, 151, 107, 50, 75, 122, 251, 234, 209, 178, 111, 80, 230, 14, 6, 113, 195, 16, 13, 238, 57, 93, 199, 6, 23, 240, 111, 230, 205, 39, 123, 45, 52, 127, 111, 229, 157, 53, 2, 255, 166, 240, 170, 113, 238, 72, 57, 60, 198, 43, 161, 251, 72, 124, 2, 213, 54, 35, 49, 38, 134, 36, 157, 200, 247, 159, 24, 12, 232, 85, 251, 235, 0, 202, 101, 1, 56, 8, 168, 160, 102, 9, 246, 227, 236, 230, 160, 187, 184, 252, 153, 185, 63, 200, 172, 147, 69, 29, 31, 177, 50, 86, 120, 193, 102, 172, 142, 48, 142, 191, 127, 107, 249, 216, 180, 198, 231, 20, 0, 7, 12, 183, 126, 112, 90, 44, 128, 4, 12, 73, 98, 70, 198, 250, 81, 102, 195, 152, 15, 236, 124, 51, 96, 216, 98, 47, 35, 46, 194, 167, 127, 215, 246, 70, 108, 239, 90, 90, 122, 48, 51, 99, 47, 201, 76, 116, 212, 120, 1, 175, 99, 237, 65, 190, 44, 28, 187, 77, 9, 28, 224, 185, 208, 52, 109, 99, 82, 87, 54, 35, 113, 141, 167, 75, 149, 59, 193, 0, 131, 158, 29, 118, 79, 49, 83, 82, 207, 165, 244, 77, 12, 183, 92, 32, 178, 250, 23, 226, 139, 79, 23, 86, 105, 1, 254, 83, 121, 92, 44, 138, 234, 21, 187, 51, 176, 63, 122, 111, 92, 211, 171, 249, 61, 116, 167, 218, 19, 250, 168, 23, 186, 249, 27, 48, 35, 244, 125, 223, 69, 188, 98, 149, 131, 173, 7, 175, 160, 19, 192, 152, 196, 176, 67, 203, 213, 239, 103, 254, 19, 141, 126, 155, 190, 157, 30, 189, 117, 201, 173, 89, 209, 133, 161, 142, 143, 3, 192, 45, 1, 31, 91, 163, 101, 55, 63, 37, 99, 141, 155, 42, 178, 199, 7, 0, 0, 0, 0, 0, 0, 0, 6, 23, 211, 59, 237, 196, 101, 207, 121, 64, 95, 39, 119, 100, 7, 61, 85, 54, 151, 122, 57, 117, 49, 102, 234, 237, 219, 43, 183, 145, 82, 27, 157, 1, 13, 161, 180, 39, 204, 186, 223, 20, 6, 219, 197, 133, 218, 235, 20, 61, 219, 5, 75, 4, 23, 151, 221, 20, 250, 23, 242, 109, 246, 50, 146, 207, 168, 229, 110, 111, 12, 61, 29, 100, 59, 113, 254, 98, 4, 57, 30, 140, 52, 245, 155, 146, 0, 181, 146, 210, 104, 250, 30, 82, 226, 65, 16, 24, 53, 107, 217, 193, 94, 226, 248, 86, 121, 63, 238, 154, 71, 46, 81, 37, 212, 74, 238, 151, 107, 55, 107, 185, 124, 26, 4, 91, 24, 158, 176, 91, 18, 200, 176, 108, 67, 123, 153, 88, 143, 156, 254, 22, 149, 252, 5, 161, 157, 7, 193, 37, 133, 12, 112, 78, 151, 133, 8, 162, 55, 89, 36, 35, 88, 17, 247, 116, 30, 43, 158, 84, 115, 38, 4, 29, 110, 168, 242, 199, 196, 193, 149, 23, 153, 15, 151, 247, 212, 164, 131, 105, 210, 116, 7, 233, 209, 165, 211, 154, 84, 134, 97, 146, 109, 38, 86, 229, 192, 106, 215, 156, 2, 58, 185, 219, 55, 99, 162, 141, 197, 175, 47, 100, 233, 79, 74, 249, 8, 172, 58, 88, 226, 39, 33, 150, 50, 167, 221, 192, 179, 214, 15, 163, 100, 44, 153, 104, 126, 210, 98, 27, 253, 106, 19, 41, 104, 119, 212, 242, 64, 3, 96, 135, 155, 123, 38, 27, 162, 146, 180, 244, 199, 161, 124, 109, 55, 96, 173, 84, 83, 110, 147, 161, 88, 251, 19, 35, 76, 96, 0, 121, 14, 177, 161, 80, 145, 94, 181, 232, 87, 233, 225, 43, 14, 132, 52, 155, 216, 153, 26, 3, 202, 72, 79, 93, 199, 81, 228, 131, 145, 112, 124, 36, 110, 13, 123, 168, 88, 249, 177, 57, 81, 151, 176, 157, 0, 154, 15, 122, 10, 242, 102, 104, 223, 129, 199, 184, 30, 129, 118, 116, 183, 250, 14, 49, 31, 173, 227, 244, 152, 71, 74, 111, 216, 213, 115, 3, 30, 44, 223, 133, 101, 107, 88, 126, 131, 240, 112, 108, 199, 181, 177, 208, 187, 64, 21, 132, 99, 85, 82, 255, 180, 128, 9, 59, 35, 192, 44, 24, 144, 13, 43, 15, 150, 102, 255, 241, 12, 90, 45, 66, 178, 175, 29, 224, 143, 193, 136, 224, 246, 8, 218, 247, 128, 248, 90, 74, 205, 204, 194, 216, 157, 0, 12, 179, 166, 40, 205, 176, 90, 80, 152, 223, 119, 53, 212, 87, 198, 235, 44, 215, 18, 59, 173, 53, 127, 85, 79, 137, 161, 162, 214, 252, 205, 136, 97, 35, 165, 199, 29, 185, 140, 32, 51, 217, 6, 180, 5, 16, 60, 238, 17, 206, 58, 6, 126, 87, 114, 238, 27, 146, 30, 146, 244, 37, 117, 183, 2, 213, 215, 233, 144, 8, 189, 113, 198, 41, 54, 69, 106, 152, 108, 213, 117, 175, 202, 93, 190, 156, 94, 8, 137, 84, 124, 190, 69, 28, 82, 71, 21, 237, 188, 224, 139, 190, 245, 159, 156, 191, 26, 15, 42, 8, 208, 216, 199, 118, 17, 67, 121, 89, 138, 60, 242, 237, 46, 134, 135, 213, 125, 103, 245, 251, 3, 69, 156, 177, 84, 183, 130, 242, 140, 91, 16, 207, 209, 114, 19, 232, 189, 184, 253, 19, 207, 27, 63, 148, 228, 251, 15, 151, 155, 127, 24, 59, 140, 190, 121, 76, 30, 79, 229, 107, 227, 36, 48, 92, 157, 227, 122, 3, 77, 56, 49, 9, 123, 86, 105, 26, 77, 120, 210, 99, 117, 166, 2, 11, 89, 56, 52, 141, 76, 197, 213, 252, 28, 139, 19, 139, 125, 191, 107, 247, 235, 219, 200, 242, 28, 113, 115, 171, 147, 2, 179, 100, 14, 82, 54, 127, 136, 88, 198, 172, 226, 167, 147, 14, 181, 24, 188, 9, 205, 231, ];

	// --- Storage ---
	#[pallet::storage]
	#[pallet::getter(fn merkle_tree)]
	pub type MerkleTree<T: Config> = StorageMap<_, Blake2_128Concat, u32, T::Hash, OptionQuery>;
	#[pallet::storage]
	#[pallet::getter(fn next_leaf_index)]
	pub type NextLeafIndex<T: Config> = StorageValue<_, u32, ValueQuery>;
	#[pallet::storage]
	#[pallet::getter(fn merkle_root)]
	pub type MerkleRoot<T: Config> = StorageValue<_, T::Hash, ValueQuery>;
	#[pallet::storage]
	#[pallet::getter(fn nullifiers)]
	pub type Nullifiers<T: Config> = StorageMap<_, Blake2_128Concat, T::Hash, (), OptionQuery>;
	#[pallet::storage]
	#[pallet::getter(fn is_relayer_registered)] // Added getter for convenience
	pub(super) type Relayers<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		bool, // true if registered, false if not (or just check existence)
		ValueQuery,
	>;
	// --- Config ---
	#[pallet::config]
	pub trait Config: frame_system::Config {
		#[pallet::constant]
		type TreeDepth: Get<u8>;
		#[pallet::constant]
		type DefaultLeafHash: Get<Self::Hash>;
		type Currency: ReservableCurrency<Self::AccountId, Balance = Self::Balance>;
    
		// New: The balance type used for fees
		type Balance: Parameter + Member + Copy + MaybeSerializeDeserialize +
			MaxEncodedLen + AtLeast32BitUnsigned + Default + CheckedSub;
		#[pallet::constant]
		type PalletId: Get<PalletId>;
		}

	// --- Events ---
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		NoteDeposited { depositor: T::AccountId, leaf_index: u32, commitment: T::Hash },
		TransferSuccessful { who: T::AccountId },
		WithdrawalSuccessful {
        recipient: T::AccountId,
        relayer: T::AccountId,
        fee: T::Balance,
    },
	}
	


	// --- Errors ---
	#[pallet::error]
	pub enum Error<T> {
		TreeFull,
		InvalidProof,
		NullifierAlreadyUsed,
		InvalidRelayer, // New: The caller is not a registered relayer.
		FeeTooLow,      // New: The relayer fee specified is insufficient.
		FeeTransferFailed,
		BalanceConversionError,
	}
	

	// --- Extrinsics ---
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(10_000, 0) + T::DbWeight::get().writes(3))]
		pub fn deposit(origin: OriginFor<T>, commitment: T::Hash) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			Self::insert_leaf(sender, commitment)?;
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(Weight::from_parts(1_000_000_000, 0) + T::DbWeight::get().writes(4))]
		pub fn transfer(
			origin: OriginFor<T>,
			proof_bytes: Vec<u8>,
			merkle_root: T::Hash,
			nullifiers: [T::Hash; 2],
			output_commitments: [T::Hash; 2],
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(merkle_root == Self::merkle_root(), Error::<T>::InvalidProof);
			ensure!(!Nullifiers::<T>::contains_key(nullifiers[0]), Error::<T>::NullifierAlreadyUsed);
			ensure!(!Nullifiers::<T>::contains_key(nullifiers[1]), Error::<T>::NullifierAlreadyUsed);

			let inputs_as_hashes = vec![
				merkle_root,
				nullifiers[0],
				nullifiers[1],
				output_commitments[0],
				output_commitments[1],
			];
			let public_inputs: Vec<Fr> = inputs_as_hashes
				.iter()
				.map(|hash| Fr::from_le_bytes_mod_order(hash.as_ref()))
				.collect();

			Self::verify_proof(public_inputs, proof_bytes)?;

			Nullifiers::<T>::insert(nullifiers[0], ());
			Nullifiers::<T>::insert(nullifiers[1], ());
			Self::insert_leaf(who.clone(), output_commitments[0])?;
			Self::insert_leaf(who.clone(), output_commitments[1])?;
			Self::deposit_event(Event::TransferSuccessful { who });
			Ok(())
		}
		#[pallet::call_index(2)] // New call index
		#[pallet::weight(Weight::from_parts(1_500_000_000, 0) + T::DbWeight::get().writes(5))]
		pub fn unshield(
			origin: OriginFor<T>,
			proof_bytes: Vec<u8>,
			merkle_root: T::Hash,
			nullifiers: [T::Hash; 2],
			output_commitments: [T::Hash; 2],
			// ZK Confirmed amount
			withdrawal_amount_h256: T::Hash, 
			relayer_address: T::AccountId, 
			recipient_address: T::AccountId, 
			fee: T::Balance, 
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			ensure!(Self::is_relayer_registered(&who), Error::<T>::InvalidRelayer);
			let min_fee: T::Balance = 100u32.into(); 
			ensure!(fee >= min_fee, Error::<T>::FeeTooLow);
			let one_fr = Fr::one();
			// 1. --- Verification Step (Placeholder) ---
			let withdrawal_u64 = {
				let mut bytes = [0u8; 8];
				bytes.copy_from_slice(&withdrawal_amount_h256.as_ref()[24..32]);
				u64::from_be_bytes(bytes)
			};
			let one_fr = Fr::one();

			let public_inputs_fr: Vec<Fr> = vec![
				one_fr,
				Fr::from_le_bytes_mod_order(withdrawal_amount_h256.as_ref()), // Input 1
				Fr::from_le_bytes_mod_order(merkle_root.as_ref()),
				Fr::from_le_bytes_mod_order(nullifiers[0].as_ref()),
				Fr::from_le_bytes_mod_order(nullifiers[1].as_ref()),
				Fr::from_le_bytes_mod_order(output_commitments[0].as_ref()),
				Fr::from_le_bytes_mod_order(output_commitments[1].as_ref()),
			];

			// ✅ Now the proof should verify
			Self::verify_proof(public_inputs_fr, proof_bytes)?;
			// 2. --- Currency Transfer Logic (The Atomic Fee Market) ---
			
			// Convert ZK amount (Fr/H256) to Pallet Balance type
			let withdrawal_amount_fr = Fr::from_le_bytes_mod_order(withdrawal_amount_h256.as_ref());
			let total_withdrawal: T::Balance = Self::fr_to_balance(withdrawal_amount_fr)
				.ok_or(Error::<T>::BalanceConversionError)?;

			// Calculate net amount for recipient (Atomicity built into DispatchResult)
			let net_recipient_amount = total_withdrawal.checked_sub(&fee)
				.ok_or(Error::<T>::FeeTransferFailed)?; 

			// Get the Pallet's AccountId (The Shielded Fund Pool)
			// FIX: Use the AccountIdConversion trait
			let pallet_account: T::AccountId = T::PalletId::get().into_account_truncating();

			// Transfer net amount to recipient
			T::Currency::transfer(
				&pallet_account, 
				&recipient_address,
				net_recipient_amount,
				// FIX: Use the correct enum variant
				ExistenceRequirement::KeepAlive, 
			).map_err(|_| Error::<T>::FeeTransferFailed)?;

			// Transfer fee to relayer
			T::Currency::transfer(
				&pallet_account, 
				&who, // Relayer is the transaction signer
				fee,
				// FIX: Use the correct enum variant
				ExistenceRequirement::KeepAlive,
			).map_err(|_| Error::<T>::FeeTransferFailed)?;

			// 3. --- State Updates ---
			
			Nullifiers::<T>::insert(nullifiers[0], ());
			Nullifiers::<T>::insert(nullifiers[1], ());
			Self::insert_leaf(who.clone(), output_commitments[0])?;
			Self::insert_leaf(who.clone(), output_commitments[1])?;

			Self::deposit_event(Event::WithdrawalSuccessful {
				recipient: recipient_address,
				relayer: who,
				fee,
			});

			Ok(())
		}
	}
		
	
		// --- Runtime Poseidon Hashing Logic ---
		// --- Helper Functions for Tests ---
	impl<T: Config> Pallet<T> {
// Function to get PoseidonConfig using hardcoded parameters
fn get_poseidon_params() -> PoseidonConfig<Fr> {
    let full_rounds = 8;
    let partial_rounds = 31;
    let alpha: u64 = 17;
    let rate = 2;
    let capacity = 1;
    let width = rate + capacity;

    // --- Hardcoded Valid Constants from poseidon_out.txt ---
    let mds_str: [[&str; 3]; 3] = [
        ["0x39855bec470bea1d8a6802e3138c3b6fe4064c7c1f8fd50e3ae21fb5e55cdab7", "0x080bfcf0a4d226355d417723cacbb65ae8e9c076fb055848b4dcbcf69d78ae28", "0x183734c7f4833244fe6930aab3c81ac7042e82f51971361aa6b1e0a98cf1398a"],
        ["0x070986505c54b6ced532b3d5690a5334ff749dbb52a044d18a40eeff3d98d575", "0x5104e34117bbc8477499413a1f1a87db8c4f012fee9d235e5fc1c0630392de58", "0x1e37753ba47b1ebfa0092b7df764e08f108e64ac41e676feef681dde99021f74"],
        ["0x2816937124301227d2ef8b4e94ee4b9c36200a679955b3c735c5d711cd83fcd8", "0x571cd1934a1790bd418de7779ad6a411bf32b63af280c96e4c00f5de2c6346be", "0x1de524140b3910478e94e5e9473fac15a3142a61de52c6e183f8e9e1fbfd5a37"]
    ];
	let mds: Vec<Vec<Fr>> = mds_str.iter().map(|row| {
        row.iter().map(|&s| {
            let s_no_prefix = s.trim_start_matches("0x");
            let mut bytes_be = hex::decode(s_no_prefix).expect("Invalid hex for MDS");
            bytes_be.reverse();
            let mut bytes_le = [0u8; 32];
            bytes_le[..bytes_be.len().min(32)].copy_from_slice(&bytes_be);
            Fr::from_le_bytes_mod_order(&bytes_le)
        }).collect()
    }).collect();
    // The flat list of 117 Round Constants (ark) from your output
    let ark_flat_str: [&str; 117] = [
    "0x3bf3daa9937bba3af988c39db9ecb39ad07f04f3c5fbcc30742fa957aeaeb330",
    "0x722c2525a218fd9041e22f9817a21f022924937f9e86920dc238c3522ddbcb86",
    "0x435c8e9b66c668d284ac98bf8dc3c48fcc9f560b2d5c3b9e10b5feac23dc2e14",
    "0x26238f7df0c8f312926367bb7136d3d611ff528edb154634355d88cc9a23f571",
    "0x6efe4e56c466c4d4f24f1707823a5cd9e4dbce1df48a9012fe0557f67595478c",
    "0x5636f290673cc1fc350f3502fc878c7a25b43f55a4b100cb478baaa1a76da5a5",
    "0x5516f1c9c723b386181ea53d127e5c088e53c05fa5d1523086197111e1d38476",
    "0x6f6a10a749dad2670605f18d43c22e3245510b84996eae0f2c351e7ada0b81f1",
    "0x21c1c31995b3786eafbe4e3730eecb2793e7e9fc060f5b52f959ac541dd0e787",
    "0x616e79027e1850669b60a5c3ace887456628abb3131648ed8798f0104d28852b",
    "0x296d948271090fdc9020362712dae16197825b155c633d1201443b5c1464fa93",
    "0x60c543741a856a310319af84d6b9c9caa6e1b68cbb8aad80a11a7b0976443a0c",
    "0x4606ae380c0c8fd1823d5a2ec2cdd08a5ca80b4f7b42c283ac22c4ab7581a753",
    "0x0f088f650d96d1dcb82332c37426c3c38994edd5215a7a9a418bf350ad7d15fb",
    "0x010ee68a920eac0bc7f52734e8975684732f068d5f653d6252423320b21891c1",
    "0x42a4280a9dc95ab18798989f30e4556e584dfc8edfada14a5fd3e19a55270be2",
    "0x100653ea547eb97fec52f83d8c69549ae282e17488da14177626efdd080cf2d2",
    "0x3f9a927951ed71976839a140f901f03dc31cedaae63bd945cb68ea6e778a2d7f",
    "0x083c1c6aa184fcbcf7c6615acee54d2e3e41221d51f5fc40c163ab6d8c0bc090",
    "0x5b35dc09e36134abcc266ae0c5d22842318cca56afef543f8af4dde7b8222138",
    "0x04080cfb3e59d324262b9fa18b3e0a9c30e798e3ccbd9000c1c94a7283e02da6",
    "0x44c4e123ef89d22aaed586eb9d0da44e22b8d26f4216b321d98401a738532075",
    "0x691f1fd854801a81d89897d154a7cf7dc3341d27a1496fc0a5b35f68b7f0227f",
    "0x6ef18262ff530c17b0856eac9287e77f3bb1a4ced5497b0ff76843301ee5765e",
    "0x13d35bb2d8bce709e154498f7e7aebc1f70c03353134f3243fdccaa0dc4da198",
    "0x3d76d86c0d4f0fcbf2c8b55e57d5785295067bf0f96bbb015d4bb6154622b1f0",
    "0x6f86c94211d970770b2be5818941958d29bd2655b37f134b9e6f5dc19ffe3f39",
    "0x5aec2494181aadfa16e76732cb99817183addcf9769196a57df5500cf7631436",
    "0x278b645d31dba8b1cde08db3e7c259b73055d972b684abb9b8ae26c00051c2fc",
    "0x1682196b52d27b46c89050c7f95053be7064731f6594b58ddd179042c982566e",
    "0x036129b9b4c54d2596fe984ef926b9eda83c02a72c529a88ae2de8c6d4755e74",
    "0x03d9290369cc60e7428329217e75bcccfcc556a6c7d49ce1c8ca3957b6cccd4c",
    "0x0a83895ed545280af06c65ad6ee15207bad59926a6bbdd04bc1bb2470106b3c5",
    "0x67d002a8cd4525c018aa520ea43bbcf1436cb82bf8a71d9b0e25ce9923d8b8ad",
    "0x201aad4bd3dee8a95eae2e453b95888e7eaf9197ad43e3f440f4b77b9d40b138",
    "0x05ebbb19fbb476b8f075308016fcf04f6027435e58f8cf92490a5d94799f48f8",
    "0x1a9cbf729b4fdc7c9f562cd6e2e8ef6ee9ac5c6801a3027cd4105f8fdbf45e27",
    "0x055db5d76ffa836f50cdc9d20f8b6e018e8451b9265fff3511bfcf2c996df576",
    "0x67d39f3a30fa2c999c50ae3d4ce5879af2bb92ef72d8c2fe182c53adffdb9395",
    "0x1122a7bcf8f3b258215fcaac203caa111f507eb2e2038d2e3b2023f9f735cfb0",
    "0x3e70155422b6c949ef035645f03a86ab25f9537c3dcdb6d3c2e6ed79ab27d3c2",
    "0x5982eda574015eee6fcb44659a0a5ae23275453b730f0f5e19cab440b50258b0",
    "0x40bf93c62c3b4d779292b4fbff8cd163bb0c06c6d6919620277a4a5fc856e4ef",
    "0x3b752b543d595f07548b7018057401588c7fbca63d4f98c2461f3ffd7a789451",
    "0x488ad599a22c4f62848ef61d7c7145fb1aea8785e66ab1dcaa292d8ed4fb24a8",
    "0x5b0a8c01298de19cf94436181e612f5ee3f9816e40daa896d101f7d739891dc3",
    "0x3148e68f573bcb55a6acbfad63a213b5ee024e1768592ca8b8353118e0eaa124",
    "0x32bd0766cee25593943100615743227db1ffde6850585ca13e3e5d0224e95912",
    "0x563398e7a9109d6995d126ea4b9300e395af0a9f1bce3646f1036eaafb4bc8d3",
    "0x4cdc53cfb5d1b97575e5f64673e1ab15e2bf14e66b909d361c40824de64be292",
    "0x073a4337d2e7dcea40ea3e1fb6f4b7cac27bb1a070409b58821f3f8f873b17b8",
    "0x32047478aec0feacf77fe8325a37c784c8710cc6cefdc2cbf5a351d6e5de4242",
    "0x154f3990f3f28775e8be2ccbc9ca8f68e282e176d59b21388c93aa144441fa29",
    "0x0b9f99277975bf24247948edaf8b2f5af7690bad84bb04f561ba919e4937f5d7",
    "0x0191c398c46a9923a5876f5105a406e96d97404c645b723e4ebde6acd241c1a2",
    "0x3245c91cc1bc5a3ee6602bf87c31d1b31f036bb7b182a406f99ded72ab04627a",
    "0x490573f3eb701854339fb0bce44fa0fa1034f47d2fc1ea7ba62a4b725cef93ee",
    "0x3c97a1b7a7559a3dd3320b6c9c0b89e5e286c4224d1549f632e02188fc1c167c",
    "0x280f96e6653fcaa56774d5e7568922b5c33e5377f287b2dec1f216b0fbc691b9",
    "0x0b01c6c084fc5a89ff0a26563e09255d2cdb4af9531ff9d810258c9a38425562",
    "0x1b10b68da8a937fe18e517b5d34a039aa7c217a6ee60f52d08e132f7fdad9aba",
    "0x47a643b526c5fa2cdd80dca105a9eeca0cb78f960b33f8f2cee66b2358d99dee",
    "0x03abfd33158615f746c3a865338811cda71ab188d57b0801cf5f8d35f2f60fd9",
    "0x69538a743a3b1acfc22de660b1c6ebb1a373eafaeed5d180c1d82cd784653cb7",
    "0x02797ced50515de0bee488d324a0e1cb05a4e2b7e96d88e5c94910de79586b05",
    "0x67e86011b5b4f626d521d39225e6f63991138fe64741df8c8c6f1c981a8391fb",
    "0x4399457226d592964da967a9968a3559a35cb65b601faffe96ce115b0ddcebe7",
    "0x1481b687e5480f0ebcc84f482cbbefe638099a98b02c03975966c2ac642a95fc",
    "0x1228f5ea3c0fb674fc4b284b0857830238582f871e8f7e9bcd47a39f90a1165e",
    "0x1a5bbf8702ab0c73367a9b61b43a66e8a7741826891cff438374c06db0686e17",
    "0x1972017add3e2adee36ca5a54543cdec75e5885f81b14f2387c0f674ad784407",
    "0x632fdb8d2e892783ea684d1eec852114d5ae962068d1f2033af4f8e9c87eb19f",
    "0x42f4f48011475c9cdaf325d30e73c3bee1af66cb04c836a300e2f78bb5e1730f",
    "0x3a03a940fc14ff2ac36a37666743401bbcd46d8283c00f7710c2d50a88a44137",
    "0x28fee1fef3a0a1fd2d4c7e6f32463ac8f34c48611c1a10ca04116dcec3dd66ee",
    "0x633308c6d4a7fdb36ab76314dc3d7437a278db2eda6de3c1245367ef3f12957d",
    "0x3aa06ffe6b263067e5a55eb20951f94035660a49138c982aafa7ef0b81cfe8f8",
    "0x6cc54da99a9d7d74d78d08ab46c05abf554e94dee0632b4073c1188fb1c87fce",
    "0x12d1a907eb97bddf840e5b656fd1a4be39be850b1d1db76e5c1b90b5e5ef1cd9",
    "0x61ac223e4b0748b62c9be2cdfc3492f7f8aa368e27abc0a99cf9555b3dc3b68d",
    "0x636014d33dc3ccaee97c4ed06a603b97cf4746044840289cf9c21ee62308508b",
    "0x310011acb69ab8eff94ed2f5fe86b9169b9f365898d1cbc49cc9fb0dca35087e",
    "0x1fdf9e74afa51025bb6e1b5bed542b045d1b2432514ce495a5b3db4fba4a5abc",
    "0x5e12597cbacf65198a7a0740c212346cd59441c16045247732f4aa9a534a32a5",
    "0x4f63fb482808740f784bf7e441fbebebc7815d24d84c7129e09f82f835ccb5a8",
    "0x0b8c76411d5c39172c23d4455ad574279431a673816c38942541bf5c7417469d",
    "0x35a61cf04dd54ed20f22e071ac168ecaca81b3bb83623c24305bc987ea18f33e",
    "0x05e99868b0d6919903d9176d69597b338c131fc895c93430725617138be73d03",
    "0x5c46ade980c248cbbb71d516d8725c7164cb410dbcd9d669762b35af57482ebe",
    "0x3d3560cad30312441649b10a720d1ba35a3a0d6a033c955223cb631554041627",
    "0x5f8da32c8c01b7487518081d3136dc2b24b88e386d798318e9ce8f971d99a417",
    "0x34cc14338c793450c8f5b9bb4d5c779f5e66648f49907dbaf6053b06564b2d6a",
    "0x4a83e5f8ed881994194666ccf3c9470a076cf8af34979389abccea37983791fb",
    "0x6bd61e16d08a9aaee0713457bc5c29d30546fb6663703132c747db1ca8dfacee",
    "0x23fc5efb9ff05e22a61eb87be50064cd3f987e9913b7b5769d24bd660f3fddc8",
    "0x4d81568e562dc5739c3fac1566730fe093d7502f57b2d918c76c5c6550aee0b7",
    "0x00c0b36e2f8fb07e18668f4360a852fcb96af00cb076aca8b702457d7ba46113",
    "0x214b7d95cff42f7ca719ee77b5b08dbe8237a1b7012ed62774f1586671ddb39e",
    "0x662fd6b62d734c6aff9ad01c683540984d880d411e5e4186bba027f7fe18217f",
    "0x10364b8a4b1f9a040b76692aa813a8dfe7c47ae1e6de447a58d225d7966c28fc",
    "0x562292d2f672f8c904425e48cde3348ddb687e4b4855687f1d6490473397e051",
    "0x1cab399be27cd9a3a72de46a9e18b7e7d5f3abd9ec6c6c84f85654f96f1eb06d",
    "0x41fc91d1e6a2eeff83e533ad52712aa70556277083d2389f5b21377c738ee16b",
    "0x390781cee15bc599b653bd9f8f1f17cbf2693fd916e5f1f512fa456c22b85888",
    "0x71c74fdfb0bcdef7d8af97ee2d08bf0104ab692bdd29e89cf8fe1224e62b63cf",
    "0x1e81344489c8af2b6cdeb22af59fab10276872e1f56dd1db190b4b6743ff9a5d",
    "0x5410e70c9b569cc5942672672671ced19594e0a4ae7c97bb50b60cd773f13b84",
    "0x6d60997011e4c0e182b8c75f3c77535dee26071f606ef2f08f4964ea3216f4df",
    "0x4f92570d66871778997cebc9ade4205a3b8df4d4359d61a70e28ff0c82f6f8f2",
    "0x1530b05ac32ee3fed68e8988ecb0bf21869adcff9fba416e1564c5875e859a8d",
    "0x1f6e961310aacd0d36fc1aa71e200b958496013ba8e1b289374f99173de54b1e",
    "0x6e40eb7e27bd6e88d0da9ec7a1b1592e3132e6e5b5c142520c85a524af9d49b2",
    "0x1c52b6f90935d4c9fd2b56726350ebb3cd5db8c4d8b663200058cb305e032b83",
    "0x6b52154118b3b760a5f4bae50a62d34031aaaa346613bc71dbd085cbd06159f0",
    "0x2bc870220358125936e9f2378c596110ebc3199a8d36e2f041ffd44f89e8fa58",
    "0x59a4093b336a2530a3ed9a4a3e8d6a667749901ead6736fd8ae78738ac2afea9",
    "0x48774cebcbaf4c11220b58f7363d8c232e26179aee5f7bf7fac5fa5b86410e02",
];
        
    // Use hex::decode and from_le_bytes_mod_order
    let mds: Vec<Vec<Fr>> = mds_str.iter().map(|row| {
        row.iter().map(|&s| {
            let s_no_prefix = s.trim_start_matches("0x");
            let mut bytes_be = hex::decode(s_no_prefix).expect("Invalid hex for MDS");
            bytes_be.reverse();
            let mut bytes_le = [0u8; 32];
            bytes_le[..bytes_be.len().min(32)].copy_from_slice(&bytes_be);
            Fr::from_le_bytes_mod_order(&bytes_le)
        }).collect()
    }).collect();

    let ark: Vec<Vec<Fr>> = ark_flat_str.chunks(width).map(|chunk| {
        chunk.iter().map(|&s| {
            let s_no_prefix = s.trim_start_matches("0x");
            if s_no_prefix.is_empty() || s_no_prefix == "0" || s_no_prefix == "00" {
                return Fr::default();
            }
            let mut bytes_be = hex::decode(s_no_prefix)
                .unwrap_or_else(|e| panic!("Invalid hex string for ARK constant: {} (Error: {:?})", s, e));
            bytes_be.reverse();
            let mut bytes_le = [0u8; 32];
            let copy_len = bytes_be.len().min(bytes_le.len());
            bytes_le[..copy_len].copy_from_slice(&bytes_be[..copy_len]);
            Fr::from_le_bytes_mod_order(&bytes_le)
        }).collect()
    }).collect();

    assert_eq!(ark.len(), full_rounds + partial_rounds, "Incorrect number of round constants provided");

    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
}

		fn hash_fr(a: Fr, b: Fr) -> Fr {
			let config = Self::get_poseidon_params();
			let mut sponge = PoseidonSponge::new(&config);
			sponge.absorb(&[a, b].as_slice());
			sponge.squeeze_field_elements(1).remove(0)
		}

		// --- Merkle Tree Logic ---
        fn calculate_zero_hashes(depth: u8, default_leaf: Fr) -> Vec<Fr> {
            let mut zero_hashes = Vec::with_capacity((depth + 1) as usize);
            let mut current_zero = default_leaf;
            zero_hashes.push(current_zero);
            for _i in 0..depth {
                current_zero = Self::hash_fr(current_zero, current_zero);
                zero_hashes.push(current_zero);
            }
            zero_hashes
        }

		pub fn insert_leaf(depositor: T::AccountId, commitment: T::Hash) -> DispatchResult {
			let leaf_index = NextLeafIndex::<T>::get();
			let max_leaves = 1u64 << T::TreeDepth::get();
			ensure!((leaf_index as u64) < max_leaves, Error::<T>::TreeFull);

			MerkleTree::<T>::insert(leaf_index, commitment);
			NextLeafIndex::<T>::put(leaf_index + 1);
			Self::update_root()?;
			Self::deposit_event(Event::NoteDeposited { depositor, leaf_index, commitment });
			Ok(())
		}

        fn update_root() -> DispatchResult {
            let depth = T::TreeDepth::get();
            let max_leaves = 1u32 << depth;
            let next_leaf_index = NextLeafIndex::<T>::get();

            if next_leaf_index == 0 {
                MerkleRoot::<T>::put(T::DefaultLeafHash::get());
                return Ok(());
            }

            let default_fr_leaf_bytes = T::DefaultLeafHash::get();
            let default_fr_leaf = Fr::from_le_bytes_mod_order(default_fr_leaf_bytes.as_ref());

            let zero_hashes = Self::calculate_zero_hashes(depth, default_fr_leaf);

            let mut current_level: Vec<Fr> = (0..max_leaves)
                .map(|i| {
                    if i < next_leaf_index {
                        let leaf_bytes = MerkleTree::<T>::get(i).unwrap_or_else(T::DefaultLeafHash::get);
                        Fr::from_le_bytes_mod_order(leaf_bytes.as_ref())
                    } else {
                        default_fr_leaf
                    }
                })
                .collect();

            for level in 0..depth {
                let mut next_level = Vec::new();
                for pair in current_level.chunks(2) {
                    let left = pair[0];
                    let right = pair[1];
                    let parent_hash = Self::hash_fr(left, right);
                    next_level.push(parent_hash);
                }
                current_level = next_level;
            }

            let new_root_fr = current_level.get(0).cloned().unwrap_or(default_fr_leaf);

            let mut root_bytes = [0u8; 32];
            let fr_bytes_vec = new_root_fr.into_bigint().to_bytes_le();
			root_bytes[..fr_bytes_vec.len().min(32)].copy_from_slice(&fr_bytes_vec);
            let new_root_hash = T::Hash::decode(&mut &root_bytes[..])
                .expect("H256 should always be decodable from [u8; 32]");

            MerkleRoot::<T>::put(new_root_hash);
            Ok(())
        }

		// NEW: Utility to convert Fr field element (used for value in ZK proof) to T::Balance
		pub fn fr_to_balance(fr: Fr) -> Option<T::Balance> {
			let big_int = fr.into_bigint(); // This is a BigInt<4>, which is a [u64; 4]

			// A T::Balance (u64 in mock) can only be represented by the first 64-bit limb.
			// We must check if any of the higher limbs (indices 1, 2, 3) are non-zero.
			// If they are, the number is too large to fit in T::Balance.
			if big_int.0[1] != 0 || big_int.0[2] != 0 || big_int.0[3] != 0 {
				return None; // Value is too large
			}

			// If only the first limb is used, we can convert it.
			// We use try_from to safely convert the u64 limb to T::Balance.
			T::Balance::try_from(big_int.0[0]).ok()
		}
		// --- ZK Proof Verification Logic ---
		pub fn verify_proof(public_inputs: Vec<Fr>, proof_bytes: Vec<u8>) -> DispatchResult {
			let vk = VerifyingKey::<Bls12_381>::deserialize_uncompressed(&VERIFYING_KEY[..])
				.map_err(|_| Error::<T>::InvalidProof)?;

			let proof = Proof::<Bls12_381>::deserialize_uncompressed(&proof_bytes[..])
				.map_err(|_| Error::<T>::InvalidProof)?;

			let is_valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)
				.map_err(|_| Error::<T>::InvalidProof)?;

			ensure!(is_valid, Error::<T>::InvalidProof);
			Ok(())
		}
	 // *** END OF impl<T: Config> Pallet<T> ***
} // *** END OF mod pallet ***
}	
// --- Module stubs for tests ---
#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;