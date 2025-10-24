#![cfg_attr(not(feature = "std"), no_std)]

// This must be at the top of the file.
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::pallet_prelude::{Decode, *};
	use frame_system::pallet_prelude::*;
	use sp_std::vec::Vec;
	
	use core::str::FromStr;
	use hex;

	// --- Arkworks Runtime Imports (v0.4.0 API) ---
	use ark_bls12_381::{Bls12_381, Fr};
	use ark_ff::{BigInteger, PrimeField, Zero};
	use ark_groth16::{Groth16, Proof, VerifyingKey};
	use ark_serialize::CanonicalDeserialize;
	use ark_snark::SNARK;
	use ark_sponge::{poseidon::{PoseidonConfig, PoseidonSponge}, CryptographicSponge};

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	// --- PASTE YOUR VERIFYING KEY BYTES HERE ---
	pub const VERIFYING_KEY: &[u8] = &[6, 2, 225, 150, 226, 28, 4, 8, 184, 78, 64, 24, 87, 210, 162, 239, 13, 34, 189, 61, 87, 8, 90, 73, 6, 51, 84, 72, 223, 27, 95, 188, 183, 43, 214, 183, 87, 162, 28, 133, 228, 14, 153, 252, 216, 128, 167, 102, 9, 63, 103, 3, 29, 153, 169, 132, 79, 202, 118, 211, 75, 174, 218, 29, 141, 2, 58, 57, 129, 255, 129, 5, 93, 211, 213, 151, 142, 4, 56, 108, 124, 37, 255, 185, 94, 128, 219, 154, 10, 87, 111, 11, 144, 240, 164, 238, 14, 253, 135, 8, 41, 115, 55, 149, 25, 60, 115, 134, 217, 115, 47, 1, 71, 130, 112, 165, 1, 66, 25, 15, 36, 5, 86, 246, 72, 68, 6, 17, 90, 62, 69, 220, 205, 159, 179, 16, 100, 212, 46, 121, 207, 185, 235, 190, 2, 14, 211, 251, 32, 203, 51, 101, 236, 48, 113, 237, 134, 76, 126, 197, 31, 47, 84, 166, 22, 56, 77, 87, 100, 104, 126, 195, 139, 177, 174, 85, 80, 168, 84, 104, 32, 33, 140, 135, 69, 166, 172, 88, 206, 102, 206, 26, 12, 238, 54, 47, 131, 31, 110, 67, 28, 161, 93, 243, 30, 30, 234, 47, 109, 151, 121, 142, 8, 242, 118, 234, 182, 127, 92, 92, 110, 199, 109, 28, 127, 26, 229, 48, 214, 234, 27, 202, 68, 164, 88, 42, 2, 174, 177, 81, 0, 90, 220, 136, 148, 30, 20, 6, 232, 174, 222, 188, 134, 207, 140, 170, 187, 41, 32, 139, 30, 105, 71, 182, 229, 180, 192, 84, 221, 50, 74, 21, 108, 244, 70, 6, 95, 250, 66, 188, 212, 123, 158, 123, 137, 243, 24, 117, 13, 41, 133, 238, 127, 239, 169, 116, 6, 201, 90, 186, 230, 19, 204, 252, 42, 72, 193, 128, 90, 137, 27, 254, 85, 248, 90, 163, 171, 48, 48, 243, 130, 155, 116, 121, 163, 182, 56, 117, 30, 185, 50, 112, 176, 118, 245, 227, 12, 134, 123, 210, 233, 237, 183, 170, 148, 183, 27, 174, 23, 52, 20, 128, 199, 51, 121, 76, 133, 232, 225, 96, 108, 52, 46, 230, 125, 19, 23, 19, 141, 133, 40, 156, 174, 144, 151, 234, 69, 56, 250, 230, 50, 226, 61, 139, 7, 205, 169, 96, 179, 146, 96, 51, 117, 135, 137, 132, 85, 250, 69, 27, 153, 143, 116, 55, 151, 171, 163, 81, 160, 23, 160, 116, 62, 241, 137, 131, 39, 135, 132, 206, 149, 29, 133, 220, 187, 175, 88, 189, 41, 52, 188, 51, 16, 190, 44, 31, 196, 247, 139, 96, 22, 133, 24, 216, 123, 242, 255, 206, 215, 98, 151, 178, 73, 105, 43, 51, 240, 145, 44, 235, 49, 39, 71, 108, 195, 168, 167, 163, 231, 68, 216, 40, 32, 196, 232, 223, 142, 24, 243, 112, 10, 146, 56, 253, 73, 22, 184, 60, 150, 108, 191, 50, 187, 226, 157, 83, 116, 160, 123, 67, 60, 208, 238, 142, 104, 81, 147, 26, 126, 23, 96, 31, 107, 102, 2, 170, 3, 49, 219, 155, 8, 26, 172, 96, 45, 149, 23, 108, 23, 103, 184, 130, 145, 85, 252, 245, 55, 28, 214, 64, 109, 126, 36, 89, 185, 240, 2, 159, 192, 97, 74, 172, 207, 218, 213, 6, 30, 244, 94, 113, 65, 240, 48, 83, 187, 208, 23, 177, 72, 184, 138, 239, 227, 168, 148, 141, 1, 156, 43, 171, 212, 115, 73, 89, 122, 147, 24, 79, 139, 213, 48, 70, 21, 58, 64, 9, 20, 154, 73, 127, 11, 17, 161, 94, 62, 165, 7, 66, 243, 165, 18, 230, 39, 235, 35, 181, 114, 141, 110, 218, 211, 113, 110, 122, 18, 152, 254, 187, 188, 47, 32, 53, 92, 173, 146, 58, 122, 115, 196, 244, 212, 53, 144, 117, 10, 21, 201, 31, 203, 213, 144, 147, 71, 182, 157, 210, 191, 11, 129, 220, 255, 254, 169, 181, 223, 161, 187, 90, 48, 165, 240, 121, 6, 0, 0, 0, 0, 0, 0, 0, 2, 79, 234, 180, 73, 246, 24, 226, 13, 83, 45, 181, 142, 114, 84, 205, 9, 216, 57, 28, 232, 108, 16, 247, 194, 106, 87, 232, 114, 139, 30, 254, 65, 64, 227, 70, 34, 235, 120, 69, 195, 92, 236, 201, 41, 25, 0, 25, 20, 45, 246, 33, 222, 189, 90, 74, 19, 43, 132, 222, 158, 199, 71, 196, 24, 57, 117, 93, 63, 139, 188, 228, 139, 232, 65, 160, 7, 190, 132, 157, 14, 225, 96, 130, 147, 232, 24, 214, 54, 166, 13, 140, 3, 166, 93, 200, 0, 23, 201, 199, 108, 95, 78, 116, 23, 17, 211, 253, 172, 62, 212, 18, 143, 232, 230, 149, 220, 102, 114, 114, 117, 81, 115, 42, 56, 226, 242, 60, 150, 247, 42, 63, 92, 60, 245, 188, 252, 235, 146, 57, 119, 186, 154, 51, 13, 65, 156, 21, 63, 142, 64, 189, 158, 189, 25, 249, 238, 245, 179, 217, 174, 35, 63, 13, 248, 153, 151, 198, 116, 169, 24, 147, 89, 59, 136, 184, 14, 208, 89, 90, 246, 94, 238, 235, 242, 195, 160, 178, 172, 26, 14, 225, 22, 96, 200, 42, 46, 126, 226, 48, 145, 44, 182, 249, 210, 56, 233, 66, 233, 40, 111, 233, 3, 203, 24, 38, 12, 160, 125, 64, 74, 224, 47, 144, 18, 239, 124, 93, 32, 78, 81, 142, 88, 52, 206, 80, 225, 23, 76, 40, 15, 170, 28, 147, 6, 183, 89, 113, 49, 140, 237, 107, 173, 123, 187, 89, 164, 141, 1, 77, 4, 104, 117, 5, 98, 97, 140, 4, 189, 97, 137, 114, 74, 127, 158, 109, 54, 226, 23, 240, 138, 112, 141, 3, 72, 175, 160, 132, 19, 4, 121, 158, 234, 157, 55, 62, 218, 218, 219, 194, 85, 35, 0, 68, 98, 70, 104, 122, 105, 73, 86, 126, 226, 4, 49, 16, 61, 246, 100, 21, 130, 239, 163, 208, 147, 9, 230, 162, 63, 29, 142, 144, 22, 107, 49, 145, 2, 143, 142, 170, 156, 182, 226, 68, 114, 229, 80, 200, 109, 45, 76, 178, 14, 226, 35, 9, 232, 24, 139, 187, 79, 155, 20, 153, 209, 65, 42, 15, 62, 120, 107, 108, 71, 204, 21, 141, 37, 70, 63, 201, 251, 147, 28, 50, 13, 74, 67, 100, 93, 233, 93, 164, 217, 111, 132, 173, 125, 148, 19, 188, 192, 12, 245, 129, 161, 194, 233, 128, 242, 104, 29, 28, 87, 172, 221, 248, 198, 109, 48, 102, 129, 161, 76, 182, 160, 157, 6, 21, 205, 207, 131, 80, 0, 127, 1, 44, 223, 40, 142, 149, 182, 213, 204, 73, 93, 141, 38, 119, 136, 190, 150, 38, 99, 218, 233, 179, 128, 13, 191, 247, 14, 67, 238, 84, 156, 226, 187, 255, 112, 64, 30, 249, 163, 149, 156, 7, 142, 89, 13, 173, 17, 197, 68, 61, 0, 48, 140, 97, 176, 188, 179, 233, 63, 64, 150, 180, 132, 67, 215, 175, 153, 34, 247, 204, 176, 191, 252, 191, 178, 82, 211, 175, 111, 105, 157, 124, 214, 80, 245, 65, 203, 50, 75, 130, 210, 1, 95, 199, 20, 67, 6, 69, 136, 116, 248, 222, 229, 239, 114, 218, 8, 17, 18, 189, 149, 109, 28, 104, 42, 137, 197, 235, 247, 200, 187, 39, 45, 193, 164, 48, 239, 57, 155, 29, 20, 177, 202, 68, 250, 156, 2, 161, 168, 104, 159, 160, ];


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

	// --- Config ---
	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		#[pallet::constant]
		type TreeDepth: Get<u8>;
		#[pallet::constant]
		type DefaultLeafHash: Get<Self::Hash>;
	}

	// --- Events ---
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		NoteDeposited { depositor: T::AccountId, leaf_index: u32, commitment: T::Hash },
		TransferSuccessful { who: T::AccountId },
	}

	// --- Errors ---
	#[pallet::error]
	pub enum Error<T> {
		TreeFull,
		InvalidProof,
		NullifierAlreadyUsed,
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
	}

	// --- Internal Logic ---
	impl<T: Config> Pallet<T> {
		// --- Runtime Poseidon Hashing Logic ---
		// --- Helper Functions for Tests ---

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
	} // *** END OF impl<T: Config> Pallet<T> ***
} // *** END OF mod pallet ***

// --- Module stubs for tests ---
#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;