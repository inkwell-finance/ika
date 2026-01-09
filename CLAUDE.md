# Ika Package

Ika 2PC-MPC dWallet network - forked from dwallet-labs/ika with Inkwell additions.

## Inkwell Additions

### Native Signing Service (`crates/ika-signing-service/`)

A native Rust HTTP service for ~4x faster 2PC-MPC signatures (2s vs 8s with WASM).

```bash
# Run the signing service
pnpm ika:signing-service

# Or directly
IKA_COORDINATOR_ID=<coordinator-id> cargo run --release -p ika-signing-service
```

**Features:**
- Fetches protocol_pp from chain on startup (~1.4s)
- Caches with version-based invalidation
- Validates cache on every sign request (~5ms overhead)
- Falls back gracefully if chain fetch fails

**Endpoints:**
- `GET /health` - Health check
- `GET /status` - Cache status (size, version, age)
- `POST /refresh` - Force cache refresh
- `POST /sign` - Sign message

**Environment Variables:**
- `SUI_RPC_URL` - Sui RPC endpoint (default: http://127.0.0.1:9000)
- `IKA_COORDINATOR_ID` - Ika coordinator object ID
- `PORT` - Service port (default: 3100)

### TypeScript SDK Additions (`sdk/typescript/`)

- `native-signing-client.ts` - Client for native signing service
- Updated `wasm-loader.ts` - Automatically uses native signing when available

```typescript
import { configureNativeSigning, checkNativeSigningHealth } from '@ika.xyz/sdk';

configureNativeSigning({ url: 'http://localhost:3100' });
const healthy = await checkNativeSigningHealth();
```

## Structure

```
contracts/
├── ika/                     # Core Ika contracts
├── ika_common/              # Common utilities
├── ika_dwallet_2pc_mpc/     # dWallet coordinator
└── ika_system/              # System contracts

crates/
├── ika-signing-service/     # Native signing HTTP service (Inkwell)
├── dwallet-mpc-centralized-party/  # MPC signing logic
└── ...                      # Other Ika crates

sdk/
├── typescript/              # TypeScript SDK
│   └── src/client/
│       ├── ika-client.ts    # Main client
│       ├── wasm-loader.ts   # WASM/native signing
│       └── native-signing-client.ts  # Native signing (Inkwell)
└── ika-wasm/               # WASM bindings
```

## Commands

```bash
# Build SDK
pnpm ika:sdk:build

# Build contracts
pnpm ika:contracts:build

# Start Ika localnet node
pnpm ika:localnet:start

# Stop Ika localnet node
pnpm ika:localnet:stop

# Run native signing service
pnpm ika:signing-service
```

## Performance Comparison

| Method | Time | Notes |
|--------|------|-------|
| WASM signing | ~8s | Browser/Node.js |
| Native signing | ~2s | Rust HTTP service |
| Protocol PP derivation | ~32ms (WASM) / ~1.4s (native fetch from chain) | One-time on startup |

## Integration

The native signing service is designed for backend-controlled dWallets where:
1. The backend holds the user secret share
2. Fast signing is needed (e.g., high-frequency trading)
3. The 44MB protocol_pp transfer is prohibitive

For browser-based dWallets with user-held shares, continue using WASM.
