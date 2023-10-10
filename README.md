# Learning SSL

Learning SSL include teninge QAT openssl and gm

## Version

- Tengine: Tag `3.0.0`
- GMSSL: Tag `v3.1.0`
- Openssl: `OpenSSL_1_1_1w`

## Docs

- [tengine draft](./docs/tengine/tengine_draft.md)
- [openssl draft](./docs/openssl/openssl_draft.md)
- [qat draft](./docs/qat/qat_draft.md)

## Reference

- [Tengine](http://tengine.taobao.org/)
- [Tengine-ngx_http_ssl_asynchronous_mode](http://tengine.taobao.org/document/ngx_http_ssl_asynchronous_mode.html)
- [Tengine-qat_ssl](http://tengine.taobao.org/document/tengine_qat_ssl.html)

- [QAT](https://01.org/intel-quickassist-technology)
    - [QAT+Openssl](https://www.intel.com/content/www/us/en/content-details/706024/intel-quickassist-technology-intel-qat-and-openssl-1-1-0-performance.html?wapkw=QAT%20performance)

### Blog

#### English

#### Chinese

- [TLS加速技术: QAT解决方案](https://www.bilibili.com/read/cv23857330/)
- [QAT场景下的openssl框架](https://www.cnblogs.com/hugetong/p/14363775.html)
- [openssl async模块框架分析](https://www.cnblogs.com/hugetong/p/14379347.html)
- [openssl 协程](https://www.cnblogs.com/hugetong/p/14378526.html)
- [openssl asynch mode 使用libasan时的oom问题](https://www.cnblogs.com/hugetong/p/14231782.html)

## Performance Points

<!-- 硬件只是基础, 提高QAT的利用率, 降低CPU的切换开销和等待时间是性能最大化的核心工作 -->
- translate to English: Hardware is just the foundation. Improving the utilization of QAT, reducing the switching overhead and waiting time of CPU are the core work of maximizing performance.

## How to gdb async ssl

1. set break point at next line of `setjmp`
    - beacuse `setjmp` will return twice, one is `0`, another is `val` of `longjmp(env, val)`
2. set break point at `func` of `makecontext(func)`
    - beacuse `func` will be called when `swapcontext` is called, that is, when `longjmp` is called

## Learning Plan

- [ ] Tengine SSL
    - [ ] Normal SSL
    - [ ] Async SSL
    - [ ] SSL enhancement
- [ ] GMSSL
- [ ] Openssl
- [ ] QAT
