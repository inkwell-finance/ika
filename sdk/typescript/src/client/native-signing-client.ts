// Native Signing Service Client
// Calls the native Rust signing service for ~4x faster signing than WASM

export interface NativeSigningConfig {
	url: string; // e.g., "http://localhost:3100"
	timeout?: number; // ms, default 30000
}

export interface SignRequest {
	protocolPublicParameters?: Uint8Array; // Optional - server uses cached if not provided
	publicOutput: Uint8Array;
	userSecretKeyShare: Uint8Array;
	presign: Uint8Array;
	message: Uint8Array;
	hash: number;
	signatureScheme: number;
	curve: number;
}

export interface SignResponse {
	signature: Uint8Array;
	durationMs: number;
}

let nativeSigningConfig: NativeSigningConfig | null = null;

/**
 * Configure the native signing service.
 * Call this at startup to enable native signing (~4x faster than WASM).
 *
 * @example
 * ```typescript
 * import { configureNativeSigning } from '@ika.xyz/sdk';
 *
 * // Enable native signing
 * configureNativeSigning({ url: 'http://localhost:3100' });
 * ```
 */
export function configureNativeSigning(config: NativeSigningConfig | null): void {
	nativeSigningConfig = config;
	if (config) {
		console.log(`[NativeSigning] Configured: ${config.url}`);
	} else {
		console.log('[NativeSigning] Disabled, using WASM');
	}
}

/**
 * Check if native signing is configured.
 */
export function isNativeSigningEnabled(): boolean {
	return nativeSigningConfig !== null;
}

/**
 * Get the current native signing configuration.
 */
export function getNativeSigningConfig(): NativeSigningConfig | null {
	return nativeSigningConfig;
}

/**
 * Call the native signing service.
 * Returns null if native signing is not configured.
 */
export async function callNativeSigningService(req: SignRequest): Promise<SignResponse | null> {
	if (!nativeSigningConfig) {
		return null;
	}

	const { url, timeout = 30000 } = nativeSigningConfig;

	// Convert Uint8Array to base64
	const toBase64 = (arr: Uint8Array): string => {
		if (typeof Buffer !== 'undefined') {
			return Buffer.from(arr).toString('base64');
		}
		// Browser fallback
		let binary = '';
		for (let i = 0; i < arr.length; i++) {
			binary += String.fromCharCode(arr[i]);
		}
		return btoa(binary);
	};

	const fromBase64 = (str: string): Uint8Array => {
		if (typeof Buffer !== 'undefined') {
			return new Uint8Array(Buffer.from(str, 'base64'));
		}
		// Browser fallback
		const binary = atob(str);
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) {
			bytes[i] = binary.charCodeAt(i);
		}
		return bytes;
	};

	const body = JSON.stringify({
		// Only include protocol_pp if provided - server uses cached otherwise
		...(req.protocolPublicParameters && req.protocolPublicParameters.length > 0
			? { protocol_pp: toBase64(req.protocolPublicParameters) }
			: {}),
		dkg_output: toBase64(req.publicOutput),
		secret_share: toBase64(req.userSecretKeyShare),
		presign: toBase64(req.presign),
		message: toBase64(req.message),
		curve: req.curve,
		signature_algorithm: req.signatureScheme,
		hash_scheme: req.hash,
	});

	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeout);

	try {
		const t0 = Date.now();
		const response = await fetch(`${url}/sign`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body,
			signal: controller.signal,
		});

		clearTimeout(timeoutId);

		if (!response.ok) {
			const errorText = await response.text();
			console.error(`[NativeSigning] Error response (${response.status}):`, errorText);
			let errorMsg = response.statusText;
			try {
				const errorJson = JSON.parse(errorText);
				errorMsg = errorJson.error || errorMsg;
			} catch {
				errorMsg = errorText || errorMsg;
			}
			throw new Error(`Native signing failed: ${errorMsg}`);
		}

		const result = await response.json();
		const totalTime = Date.now() - t0;

		console.log(
			`[NativeSigning] Complete: ${result.duration_ms}ms signing, ${totalTime}ms total (incl. network)`
		);

		return {
			signature: fromBase64(result.signature),
			durationMs: result.duration_ms,
		};
	} catch (error: unknown) {
		clearTimeout(timeoutId);
		if (error instanceof Error && error.name === 'AbortError') {
			throw new Error(`Native signing timeout after ${timeout}ms`);
		}
		throw error;
	}
}

/**
 * Health check for the native signing service.
 */
export async function checkNativeSigningHealth(): Promise<boolean> {
	if (!nativeSigningConfig) {
		return false;
	}

	try {
		const response = await fetch(`${nativeSigningConfig.url}/health`, {
			method: 'GET',
			signal: AbortSignal.timeout(5000),
		});
		return response.ok;
	} catch {
		return false;
	}
}
