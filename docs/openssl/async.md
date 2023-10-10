async api:

```text
ASYNC_get_current_job
    OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, NULL)
        ossl_init_async
            async_init
                CRYPTO_THREAD_init_local(&ctxkey, NULL)
                CRYPTO_THREAD_init_local(&poolkey, NULL)
            async_inited = 1
    async_get_ctx  # get async_ctx from ctxkey

    <= ctx->currjob

ssl_start_async_job(ssl_do_handshake_intern)
    if s->waitctx is NULL
        ASYNC_WAIT_CTX_new

    s->rwstate = SSL_NOTHING

    ASYNC_start_job(&s->job, waitctx, &ret, ssl_do_handshake_intern)

    switch (rc)
    {
    case ASYNC_ERR:
        s->rwstate = SSL_NOTHING
        return -1

    case ASYNC_PAUSE
        s->rwstate = SSL_ASYNC_PAUSED
        return -1

    case ASYNC_NO_JOBS:
        s->rwstate = SSL_ASYNC_NO_JOBS
        return -1

    case ASYNC_FINISH:
        s->job = NULL
        return ret

    default:
        # should not happen
        s->rwstate = SSL_NOTHING
        return -1;
    }

ASYNC_start_job(job, waitctx, ret, func, args)
    OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, NULL)
    async_get_ctx
    if (ctx is NULL)
        async_ctx_new
            malloc a new ctx
            ossl_init_thread_start(OPENSSL_INIT_THREAD_ASYNC)
            async_fibre_init_dispatcher(&ctx->dispatcher)
            CRYPTO_THREAD_set_local(&ctxkey, ctx)

    for (;;)
        if (ctx->currjob is existed)
            switch (status)
            {
            case STOPPING:
                currjob->ret => ret
                release job

                return ASYNC_FINISH

            case PAUSING:
                ctx->currjob->status = PAUSED

                return ASYNC_PAUSE;

            case PAUSED:
                # resume previous job
                async_fibre_swapcontext(&ctx->dispatcher, &ctx->currjob->fibrectx, 1)

                continue;

            default:
                Should not hanppen, if it is, return release job and return ASYNC_ERR
            }

        else
            async_get_pool_job => ctx->currjob
                CRYPTO_THREAD_get_local(&poolkey)

                if (pool is NULL)
                    ASYNC_init_thread(0, 0)
                    CRYPTO_THREAD_get_local(&poolkey)

                sk_ASYNC_JOB_pop(pool->jobs) => job # pop from sk_stack

                if (job is NULL)
                    async_job_new => job # the job->status is RUNNING
                    async_fibre_makecontext(&job->fibrectx)
                    pool->curr_size++
            if (no job in pool)
                return ASYNC_NO_JOBS

            mcopy args to ctx->currjob->funcargs

            ctx->currjob->func      = func
            ctx->currjob->waitctx   = wctx

            async_fibre_swapcontext(&ctx->dispatcher, &ctx->currjob->fibrectx, 1)

    err: error handler and return ASYNC_ERR
```

fibre:

```text
async_fibre_makecontext
    fibre->env_init = 0
    getcontext(&fibre->fibre) # get context

    # modify context to async_start_func, that is be called once at the first time
    makecontext(&fibre->fibre, async_start_func, 0)

async_fibre_swapcontext
    old->env_init = 1
    if (_setjmp(old->env) == 0)
    {
        if (new->env_init)
            _logjmp(new->env, 1)
        else
            setcontext(&n->fibre) # first time, call async_start_func
    }

    return 1

async_fibre_free
    free stack in fibre->fibre.uc_stack, and point it to NULL
```

async_start_func:

```
async_get_ctx

while (1)
    # Run the job
    job->ret = job->func(job->funcargs)

    # stop the job
    job->status = ASYNC_JOB_STOPPING
    async_fibre_swapcontext(&job->fibrectx, &ctx->dispatcher, 1)
```
