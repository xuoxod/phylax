/**
 * Phylax (φύλαξ) — Universal Sovereign Client Shield
 * Zero-dependency client-side assistant for Proof-of-Work puzzle solving,
 * honeypot decoy field management, and timing token injection.
 *
 * Compatible with Vanilla JS, React, Vue, Svelte, Angular, HTMX, and Alpine.js.
 */
(function (global) {
    'use strict';

    // Pure synchronous SHA-256 implementation (works in all browsers without crypto.subtle async friction)
    function sha256Sync(ascii) {
        function rightRotate(value, amount) {
            return (value >>> amount) | (value << (32 - amount));
        }

        const mathPow = Math.pow;
        const maxWord = mathPow(2, 32);
        let result = '';

        const words = [];
        const asciiLength = ascii.length;
        const hash = [];
        const k = [];

        let primeCounter = 0;
        const isComposite = {};
        for (let candidate = 2; primeCounter < 64; candidate++) {
            if (!isComposite[candidate]) {
                for (let i = candidate * candidate; i < 313; i += candidate) {
                    isComposite[i] = true;
                }
                if (primeCounter < 8) {
                    hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
                }
                k[primeCounter] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
                primeCounter++;
            }
        }

        words[asciiLength >> 2] |= 128 << (24 - (asciiLength % 4) * 8);
        words[(((asciiLength + 64) >> 9) << 4) + 15] = asciiLength * 8;

        for (let i = 0; i < words.length; i += 16) {
            const w = words.slice(i, i + 16);
            const oldHash = hash.slice(0);

            for (let j = 0; j < 64; j++) {
                if (j >= 16) {
                    const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                    const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                    w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
                }

                const s1 = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
                const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
                const temp1 = (hash[7] + s1 + ch + k[j] + w[j]) | 0;
                const s0 = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
                const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
                const temp2 = (s0 + maj) | 0;

                hash[7] = hash[6];
                hash[6] = hash[5];
                hash[5] = hash[4];
                hash[4] = (hash[3] + temp1) | 0;
                hash[3] = hash[2];
                hash[2] = hash[1];
                hash[1] = hash[0];
                hash[0] = (temp1 + temp2) | 0;
            }

            for (let j = 0; j < 8; j++) {
                hash[j] = (hash[j] + oldHash[j]) | 0;
            }
        }

        for (let i = 0; i < 8; i++) {
            for (let j = 3; j >= 0; j--) {
                const b = (hash[i] >> (8 * j)) & 255;
                result += (b < 16 ? '0' : '') + b.toString(16);
            }
        }
        return result;
    }

    const Phylax = {
        currentChallenge: null,
        isSolving: false,

        /**
         * Fetch challenge context (timing token, PoW seed, and honeypot field list)
         */
        async fetchChallenge(endpoint = '/api/shield/challenge') {
            try {
                const res = await fetch(endpoint);
                if (!res.ok) return null;
                const data = await res.json();
                this.currentChallenge = data;

                // Start solving in background immediately so it's ready before form submission
                this.solveCurrentChallenge();
                return data;
            } catch (e) {
                console.warn('🛡️ [Phylax] Unable to fetch challenge:', e);
                return null;
            }
        },

        /**
         * Solve the Proof-of-Work challenge in a non-blocking chunked loop
         */
        solveCurrentChallenge() {
            if (!this.currentChallenge || this.isSolving || this.currentChallenge.nonce !== undefined) {
                return;
            }
            this.isSolving = true;
            const seed = this.currentChallenge.pow_seed;
            const difficulty = this.currentChallenge.pow_difficulty || 14;

            const fullBytes = Math.floor(difficulty / 8);
            const remainingBits = difficulty % 8;

            let nonce = 0;
            const startTime = performance.now();

            const solveChunk = () => {
                const iterationsPerChunk = 5000;
                for (let i = 0; i < iterationsPerChunk; i++, nonce++) {
                    const input = seed + ':' + nonce;
                    const hashHex = sha256Sync(input);

                    let valid = true;
                    for (let b = 0; b < fullBytes; b++) {
                        if (hashHex.substr(b * 2, 2) !== '00') {
                            valid = false;
                            break;
                        }
                    }

                    if (valid && remainingBits > 0) {
                        const nextByte = parseInt(hashHex.substr(fullBytes * 2, 2), 16);
                        const mask = 0xFF << (8 - remainingBits);
                        if ((nextByte & mask) !== 0) {
                            valid = false;
                        }
                    }

                    if (valid) {
                        this.currentChallenge.nonce = nonce;
                        this.isSolving = false;
                        const elapsed = (performance.now() - startTime).toFixed(1);
                        console.debug(`🛡️ [Phylax] PoW solved in ${elapsed}ms (nonce: ${nonce})`);
                        return;
                    }
                }

                // Yield to browser UI thread
                setTimeout(solveChunk, 0);
            };

            solveChunk();
        },

        /**
         * Attach challenge tokens and solved PoW nonce to outgoing request payload
         */
        enrichPayload(payloadObj) {
            if (!this.currentChallenge) return payloadObj;
            return {
                ...payloadObj,
                timing_token: this.currentChallenge.timing_token,
                pow_challenge: this.currentChallenge.pow_challenge,
                pow_nonce: this.currentChallenge.nonce || 0,
            };
        }
    };

    global.Phylax = Phylax;

    // Auto-fetch challenge on page load if challenge meta tag is present
    if (typeof document !== 'undefined') {
        document.addEventListener('DOMContentLoaded', () => {
            const meta = document.querySelector('meta[name="phylax-challenge"]');
            if (meta) {
                const endpoint = meta.getAttribute('content') || '/api/shield/challenge';
                Phylax.fetchChallenge(endpoint);
            }
        });
    }

})(typeof window !== 'undefined' ? window : global);
