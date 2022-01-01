
#define C2S "c2s.com"
#define S2C "s2c.com"

static int fileCbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl;
    int frecv = *(int *)ctx;
    int ret = 0;

    while (ret <= 0) {
        ret = (int)read(frecv, buf, (size_t)sz);
    }
    return ret;
}

static int fileCbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl;
    int fsend = *(int *)ctx;

    return (int)write(fsend, buf, (size_t)sz);
}

static int fsend;
static int frecv;
