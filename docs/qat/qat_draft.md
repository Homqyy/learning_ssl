# Draft of QAT

Big/Small request offload
    - set threshold by `SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD`

pipeline
    - To parallelize the encryption of TLS records, type must be independent from a cryptographic perspective. For this reason, pipelining isnly supported for TLSv1.1 and TLSv1.2, where the IV is explicit, and does not depend on the previous record.
    - There is currently no support for SSLv3, TLSv1.0, or DTLS (all versions) in the OpenSSL-1.1.0 branch. ( Does was supported in openssl-1.1.1 or 3.0.0? )
