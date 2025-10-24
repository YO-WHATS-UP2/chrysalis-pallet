Chrysalis: A Substrate Pallet for Private ZK-Transfers
This project implements pallet-chrysalis, a Substrate FRAME pallet that enables private, anonymous transfers using zero-knowledge proofs (ZK-SNARKs).

The core functionality allows users to deposit (shield) funds into an on-chain Merkle tree and then privately spend or transfer them by providing a Groth16 ZK proof. This proof cryptographically demonstrates ownership and balance without revealing the sender, receiver, or transaction amount.

Core Components
The project consists of three main Rust crates that work together:

pallet-chrysalis (The Pallet)

This is the on-chain runtime logic.

deposit(commitment) extrinsic: Allows a user to add a new note commitment (a hash) to the pallet's MerkleTree storage.

transfer(...) extrinsic: The core function. It accepts a proof, a merkle_root, a list of nullifiers to be spent, and new output_commitments to be created.

Verifier: It contains the on-chain logic to call Groth16::verify using the hardcoded Verifying Key (VK), ensuring the provided proof is valid for the given public inputs.

State Management: If verification succeeds, it adds the nullifiers to a "spent list" (preventing double-spends) and inserts the new output_commitments into the MerkleTree.

Hashing: All on-chain cryptographic operations (Merkle root updates, etc.) use the Poseidon hash function, which is efficient to compute within ZK circuits.

chrysalis-circuit (The Circuit)

This crate defines the rules of a valid transfer using arkworks (v0.4.0) and ark-r1cs-std.

It contains the PrivateTransferCircuit struct, which defines the constraint system (the "rules") for the ZK-SNARK.

This circuit enforces:

Merkle Path Verification: Proves that the input notes being spent are valid members of the on-chain Merkle tree.

Nullifier Check: Proves that the nullifiers are correctly derived from the input notes' secrets.

Value Conservation: Proves that sum(input_values) == sum(output_values).

Output Generation: Proves that the new output commitments are correctly calculated.

tools/generate_test_data (The Prover Tool)

A standalone binary created to solve the memory-intensive task of proof generation. cargo test on a typical machine would run out of memory (SIGKILL).

Mode 1 (Setup): Generates the matching Proving Key (PK) and Verifying Key (VK) for the circuit.

Mode 2 (Proving): Uses the PROVING_KEY_BYTES, hardcoded Poseidon parameters, and a set of test inputs (notes, paths, etc.) to generate a valid test_proof.bin and test_pub_inputs.json file.

Development Journey & Core Logic
The primary goal was to achieve a successful end_to_end_transfer_should_succeed test. This involved several key challenges and solutions:

1. The Challenge: Resource Exhaustion (SIGKILL)
Problem: Running Groth16::prove inside cargo test consumed too much RAM, causing the operating system to kill the test.

Solution: We adopted a two-step approach:

Offline Proof Generation: We built the generate_test_data tool to run the memory-heavy prove function once and save the resulting proof and public inputs to files (test_proof.bin, test_pub_inputs.json).

Lightweight Test: The end_to_end_transfer_should_succeed test was modified to load these files from the pallets/chrysalis/src/testdata/ directory instead of generating the proof. This makes the test fast and low-memory.

2. The Challenge: Merkle Tree Complexity
Problem: A TreeDepth of 32 was still too large for the proof generator tool.

Solution: We reduced the TreeDepth to 2 across all parts of the project:

mock.rs (pallet testing)

chrysalis-circuit/src/lib.rs (circuit definition)

tools/generate_test_data/src/main.rs (proof generation)

3. The Challenge: Cryptographic Consistency
Problem: The test failed with InvalidProof because the Merkle root calculated by the pallet on-chain did not match the root calculated by the offline tool.

Solution: This was traced to inconsistencies in the Poseidon hash parameters (ark and mds). We fixed this by:

Using a SageMath script (generate_params_poseidon.sage) to generate a single, definitive set of real, non-zero constants for our parameters (alpha=17, width=3, rf=8, rp=31).

Fixing typos in the generator's output.

Copy-pasting this identical set of hardcoded constants into lib.rs, tests.rs, and main.rs.

Ensuring the update_root logic in the pallet correctly mirrored the logic used by the circuit and test generator.

4. The Final Success: The end_to_end_transfer_should_succeed Test
The final, passing test now executes this flow:

Load: Reads the pre-generated test_proof.bin and test_pub_inputs.json.

Deposit: Calls deposit twice to insert the two initial commitments (C1, C2) from the JSON file.

Assert Root: Confirms the pallet's calculated on-chain MerkleRoot perfectly matches the merkle_root from the JSON file.

Call Transfer: Calls pallet::transfer with the loaded proof and public inputs.

Verify: The pallet's verify_proof function succeeds because the VERIFYING_KEY in lib.rs matches the PROVING_KEY_BYTES used to create the proof.

Assert State: The test confirms that the next_leaf_index is 4, the nullifiers are marked as spent, and the new output commitments (C3, C4) are in the tree.

Technical Stack
Blockchain: Substrate (stable2509 branch)

Language: Rust

Zero-Knowledge: arkworks v0.4.0

Proof System: Groth16 (ark-groth16)

Constraint System: ark-r1cs-std

Hash Function: Poseidon (ark-sponge, ark-crypto-primitives)

How to Test
Prerequisites:

Ensure the chrysalis-circuit crate has been modified for TreeDepth = 2.

Ensure pallets/chrysalis/src/testdata/ contains the test_proof.bin and test_pub_inputs.json files generated for the TreeDepth = 2 circuit.

Run the tests from the root of the substrate workspace:

Bash

cargo test -p pallet-chrysalis --lib --features std
