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

## Coding Style

### Chapter 1: Indentation

Pre-processor directives use one space for indents:

```c
    #if
    # define
    #else
    # define
    #endif
```

### Chapter 3.1: Spaces

When declaring pointer data or a function that returns a pointer type, the asterisk goes next to the data or function name, and not the type:

```c
    char *openssl_banner;
    unsigned long long memparse(char *ptr, char **retptr);
    char *match_strdup(substring_t *s);
```

Avoid empty lines at the beginning or at the end of a file.

Avoid multiple empty lines in a row.

### Chapter 4: Naming

For getter functions returning a pointer and functions setting a pointer given as a parameter, use names containing get0_ or get1_ (rather than get_) or set0_ or set1_ (rather than set_) or push0_ or push1_ (rather than push_) to indicate whether the structure referred to by the pointer remains as it is or it is duplicated/up-ref’ed such that an additional free() will be needed.

Use lowercase prefix like ossl_ for internal symbols unless they are static (i.e., local to the source file).

Use uppercase prefix like EVP_ or OSSL_CMP_ for public (API) symbols.

### Chapter 5: Typedefs

OpenSSL uses typedef’s extensively. For structures, they are all uppercase and are usually declared like this:

```c
    typedef struct name_st NAME;
```

A final word on struct’s. OpenSSL has historically made all struct definitions public; this has caused problems with maintaining binary compatibility and adding features. Our stated direction is to have struct’s be opaque and only expose pointers in the API. The actual struct definition should be defined in a local header file that is not exported.

### Chapter 6: Functions

A public function should verify that its arguments are sensible

Where an extended function should be added the original function should be kept and a new version created with the same name and an _ex suffix. For example, the RAND_bytes function has an extended form called RAND_bytes_ex.Where an extended version of a function already exists and a second extended version needs to be created then it should have an _ex2 suffix, and so on for further extensions.

### Chapter 8: Commenting

Use the classic /* ... */ comment markers. Don’t use // ... markers.

```c
    /*-
     * This is the preferred style for multi-line
     * comments in the OpenSSL source code.
     * Please use it consistently.
     *
     * Description:  A column of asterisks on the left side,
     * with beginning and ending almost-blank lines.
     */
```

Place comments above or to the right of the code they refer to. Comments referring to the code line after should be indented equally to that code line.

### Chapter 9: Macros and Enums

Macro names should be in uppercase, but macros resembling functions may be written in lower case. Generally, inline functions are preferable to macros resembling functions.

Macros with multiple statements should be enclosed in a do - while block:

```c
    #define macrofun(a, b, c)   \
        do {                    \
            if (a == 5)         \
                do_this(b, c);  \
        } while (0)
```

Do not write macros that depend on having a local variable with a magic name:

```c
    #define FOO(val) bar(index, val)
```

Do not write macros that are l-values:

```c
    FOO(x) = y
```

Macros defining an expression must enclose the expression in parentheses unless the expression is a literal or a function application:

```c
    #define SOME_LITERAL 0x4000
    #define CONSTEXP (SOME_LITERAL | 3)
    #define CONSTFUN foo(0, CONSTEXP)
```

### Chapter 10: Allocating memory

OpenSSL provides many general purpose memory utilities, including, but not limited to: `OPENSSL_malloc()`, `OPENSSL_zalloc()`, `OPENSSL_realloc()`, `OPENSSL_memdup()`, `OPENSSL_strdup()` and `OPENSSL_free()`. Please refer to the API documentation for further information about them.

### Chapter 11: Function return values and names

Functions can return values of many different kinds, and one of the most common is a value indicating whether the function succeeded or failed. Usually this is:

1: success
0: failure
Sometimes an additional value is used:

-1: something bad (e.g., internal error or memory allocation failure)
Other APIs use the following pattern:

>= 1: success, with value returning additional information
<= 0: failure with return value indicating why things failed
Sometimes a return value of -1 can mean “should retry” (e.g., BIO, SSL, et al).

### Chapter 14: Portability

To maximise portability the version of C defined in ISO/IEC 9899:1990 should be used. This is more commonly referred to as C90. ISO/IEC 9899:1999 (also known as C99) is not supported on some platforms that OpenSSL is used on and therefore should be avoided.

### Chapter 16: Asserts

Use OPENSSL_assert() only in the following cases: - In the libraries when the global state of the software is corrupted and there is no way to recover it - In applications, test programs and fuzzers

Use ossl_assert() in the libraries when the state can be recovered and an error can be returned. Example code:

```c
    if (!ossl_assert(!should_not_happen)) {
        /* push internal error onto error stack */
        return BAD;
    }
```

Use assert() in libraries when no error can be returned.

## Terms

Term | Description
--- | ---
PSK     | Pre-Shared Key
ossl    | abbreviation of OpenSSL

## Interface/Object

Problems:

- Create ex_data index in `SSL_CTX`, finally how to affect `SSL`?
- Why is twice defined for `SSL_METHOD` and they are different?
    - valid defined in `ssl/methods.c`
- what is boringssl?

### SSL_CTX

### SSL_METHOD

### SSL

`SSL_set_accept_state` or `SSL_set_connect_state` will set a handshake function to `SSL.handshake_func`, the value ether is `ssl3_connect`(`SSL.method->connect`) or `ssl3_accept`(`SSL.method->accept`).

## Reference

- [man1.1.1 of openssl](https://www.openssl.org/docs/man1.1.1/man3/)
- [Coding Style of openssl](https://www.openssl.org/policies/technical/coding-style.html)
- [Coding Style of kernel](https://www.kernel.org/doc/Documentation/process/coding-style.rst)
- [Strategic Architecture of openssl](https://www.openssl.org/docs/OpenSSLStrategicArchitecture.html)
