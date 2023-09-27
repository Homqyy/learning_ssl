# Draft of openssl



Openssl consists of 4 parts:

- Applications Component    (bin/*)
- TLS Component             (libssl.*)
- Crypto Component          (libcrypto.*)
- Engines Component         (engines-*/*)

<figure>
    <img alt="openssl_components" src="/docs/assets/openssl_components.png">
    <figcaption>openssl_components</figcaption>
</figure>

Framework of openssl in async mode:

<figure>
    <img alt="framework_of_openssl_in_async_mode" src="/docs/assets/framework_of_openssl_in_async_mode.png">
    <figcaption>framework_of_openssl_in_async_mode</figcaption>
</figure>

1. App invoke API of TLS Component
2. TLS Component invoke API of Crypto Component
3. Crypto Component invoke API of Engines Component

Initialize openssl for different applications:

- ssl application: `OPENSSL_init_ssl()`
- crypto application: `OPENSSL_init_crypto()`

## reference

- [man1.1.1 of openssl](https://www.openssl.org/docs/man1.1.1/man3/)