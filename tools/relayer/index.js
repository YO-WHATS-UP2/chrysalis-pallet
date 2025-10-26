import express from 'express';
import bodyParser from 'body-parser';
import { config } from 'dotenv';
import { ApiPromise, WsProvider } from '@polkadot/api';

// Load environment variables from .env file
config();

const app = express();
app.use(bodyParser.json());

// --- Configuration ---
const nodeUrl = process.env.SUBSTRATE_NODE_URL;
const PORT = process.env.PORT || 9000;

if (!nodeUrl) {
  console.error("🔥 FATAL ERROR: SUBSTRATE_NODE_URL is not set in the .env file.");
  process.exit(1);
}

// --- Main Server & Node Connection ---
async function main() {
  console.log(`Connecting to Substrate node at ${nodeUrl}...`);
  
  try {
    const provider = new WsProvider(nodeUrl);
    const api = await ApiPromise.create({ provider });
    
    console.log("✅ Successfully connected to node.");
    const chain = await api.rpc.system.chain();
    const nodeName = await api.rpc.system.name();
    const nodeVersion = await api.rpc.system.version();
    console.log(`Node: ${chain} (${nodeName} v${nodeVersion})`);

    // --- API Endpoint ---
    // Create the /submit-transaction endpoint
    app.post('/submit-transaction', (req, res) => {
      console.log("\n---");
      console.log("📨 Received payload at /submit-transaction:");
      
      // Log the received data
      console.log(JSON.stringify(req.body, null, 2));

      // For Day 11, we just acknowledge receipt.
      // Logic for verification and on-chain submission (Day 12) comes next.
      res.status(200).send({ 
        status: "received",
        message: "Payload received by relayer. Processing (placeholder)..." 
      });
    });

    // Start the server
    app.listen(PORT, () => {
      console.log(`\n🚀 Chrysalis Relayer scaffold running on http://localhost:${PORT}`);
    });

  } catch (error) {
    console.error("🔥 Failed to connect to Substrate node:", error.message);
    process.exit(1);
  }
}

main().catch(console.error);