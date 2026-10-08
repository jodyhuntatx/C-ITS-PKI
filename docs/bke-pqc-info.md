## BKE like you're five:

Imagine you have one special caterpillar, and you know a magic trick that can turn it into hundreds of different butterflies. Every butterfly looks totally different, so nobody watching can tell they all came from the same caterpillar. But you know the trick, so every butterfly is still yours.

That's butterfly key expansion.

**Why anyone wants this:** Cars that talk to each other (V2X) shout messages like "I'm braking!" many times a second. Each message needs a signature so others can trust it. If a car used the same key every time, anyone listening could follow it around town. So each car needs lots of different keys that change often, and nobody should be able to link them back to the car.

### How the trick works:

1. **You make one caterpillar.** Your car makes one secret key and shows the world only its public half. It also writes down a secret "recipe," a rule for turning that one key into key #1, key #2, key #3, and so on.
2. **You give the caterpillar and recipe to a helper.** The helper (the Registration Authority) uses the recipe to make hundreds of public "butterfly" keys from your one caterpillar. It mixes your butterflies in a big bag with butterflies from thousands of other cars.
3. **A second helper paints each butterfly.** The certificate authority picks butterflies out of the bag and adds a dab of its own random paint to each one before stamping it "official." It doesn't know which car each butterfly belongs to.
4. **Only you can recognize your butterflies.** The painted butterflies come back to your car, sealed so only you can open them. Since you know your original secret and the recipe, and the paint is sent to you, you can figure out the private key for every butterfly. Nobody else can.

### The point:

- One small request turns into hundreds or thousands of certificates, which saves a lot of bandwidth.
- The first helper knows it's your car but can't recognize the final butterflies, because the paint changed them.
- The second helper sees the butterflies but doesn't know whose they are.
- Only your car holds the private keys.

**The grown-up version in one breath:** The device sends a seed public key A plus an expansion function f. The RA derives Aᵢ = A + f(i)·G, then shuffles requests across devices. The PCA adds randomness cᵢ, issues a certificate on Aᵢ + cᵢ·G, and encrypts the response to the device. The device computes the private key a + f(i) + cᵢ. It's used in SCMS / IEEE 1609.2.1 for pseudonym certificates. There's also a "unified" variant that folds the encryption key into the same expansion, so the device sends fewer keys.

## Can butterfly key expansion work with quantum-proof ciphers?

Yes, but not as a drop-in swap. Today's quantum-resistant algorithms need some changes first, and researchers have shown it can be done.

**Why it's not automatic.** The whole trick depends on a math property: if you add something to the private key, you can add a matching something to the public key, and the two still match. Elliptic curves have this naturally ((a + b)·G = a·G + b·G). That property is what lets the helpers "paint" your butterflies without ever seeing your secret. Earlier research identified this homomorphism between the secret-key and public-key domains as the fundamental property butterfly key expansion needs. 
iacr

Quantum-resistant schemes mostly lack this property in a clean form:

- **Lattice schemes (ML-KEM/Kyber, ML-DSA/Dilithium):** These come close. Keys are roughly linear, but security depends on secrets staying small (low noise). Each round of adding random offsets makes the secret bigger. If it gets too big, signatures fail or leak information. You need tuned parameters so the butterflies still work after both rounds of painting.
- **Hash-based signatures (SLH-DSA/SPHINCS+):** These have no algebraic structure to add things to, so the trick doesn't apply.
- **Unified butterfly** (one key for both signing and encryption) is harder still. It needs encryption and signing key pairs with the same algebraic nature, which works for ECC but rules out most post-quantum candidates. 

### What's been done:

- Eaton, Lamontagne, and Matsakis at the National Research Council Canada presented the first provably secure BKE protocol built on post-quantum schemes, specifically the NIST-selected CRYSTALS family. They modified Kyber and Dilithium from LibOQS, proved the scheme is both unforgeable and unlinkable, and published parameter choices and performance results. The catch is that these are modified algorithms, not the standard FIPS 203/204 versions. 
- A January 2026 paper proposes an NTRU-based key expansion where an end entity generates a key pair once and the CA expands it into many distinct public keys, which is much faster than generating fresh pairs. 
- A patent describes RLWE-based BKE that requires a KEM and a signature scheme with additively homomorphic keys, a shared key pair, and security under the same distributions and parameters. 

**The bigger practical problem for V2X isn't BKE itself, it's size.** An ECDSA signature is about 64 bytes. An ML-DSA signature is about 2.4 KB, and its public keys are over 1 KB. Cars broadcast safety messages roughly 10 times a second over constrained radio channels, so certificate and signature size becomes the real bottleneck. That's true whether or not butterfly expansion is used.

As far as I know, IEEE 1609.2.1 hasn't standardized a post-quantum BKE yet, so the published work is still research and proposals.

Sources:

- [Provably Secure Butterfly Key Expansion from the CRYSTALS Post-Quantum Schemes (IACR ePrint 2024/946)](https://eprint.iacr.org/2024/946)
- [Post-Quantum Cryptography Key Expansion Method and Anonymous Certificate Scheme Based on NTRU (arXiv 2601.07841)](https://www.arxiv.org/abs/2601.07841)
- [Systems and methods for a butterfly key exchange program (USPTO 11165592)](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11165592)
