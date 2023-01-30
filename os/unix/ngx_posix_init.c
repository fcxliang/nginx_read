
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>


ngx_int_t   ngx_ncpu; //CPU核数
ngx_int_t   ngx_max_sockets;  //系统支持的最大socket数
ngx_uint_t  ngx_inherited_nonblocking;
ngx_uint_t  ngx_tcp_nodelay_and_tcp_nopush;


struct rlimit  rlmt;


ngx_os_io_t ngx_os_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    ngx_udp_unix_recv,
    ngx_unix_send,
    ngx_udp_unix_send,
    ngx_udp_unix_sendmsg_chain,
    ngx_writev_chain,
    0
};

/*
	设置系统参数
	ngx_linux_kern_ostype   	操作系统类型
	ngx_linux_kern_osrelease  	发行版本
	ngx_pagesize 				页大小
	ngx_cacheline_size 			缓存交换大小
	ngx_max_sockets				最大socket数量
	设置随机种子
*/
ngx_int_t
ngx_os_init(ngx_log_t *log)
{
    ngx_time_t  *tp;
    ngx_uint_t   n;
#if (NGX_HAVE_LEVEL1_DCACHE_LINESIZE)
    long         size;
#endif

#if (NGX_HAVE_OS_SPECIFIC_INIT)
    if (ngx_os_specific_init(log) != NGX_OK) { //linux上为获得内核版本信息
        return NGX_ERROR;
    }
#endif

    if (ngx_init_setproctitle(log) != NGX_OK) {  //<-----若要修改进程名字从这里看起
        return NGX_ERROR;
    }

    ngx_pagesize = getpagesize();
    ngx_cacheline_size = NGX_CPU_CACHE_LINE;

    for (n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) { /* void */ } //4k的话 shift就是12

#if (NGX_HAVE_SC_NPROCESSORS_ONLN)
    if (ngx_ncpu == 0) {
        ngx_ncpu = sysconf(_SC_NPROCESSORS_ONLN);  // 获取可用的cpu核数
    }
#endif

    if (ngx_ncpu < 1) {
        ngx_ncpu = 1;
    }

#if (NGX_HAVE_LEVEL1_DCACHE_LINESIZE)
    size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);  // 获取cpu cache line
    if (size > 0) {
        ngx_cacheline_size = size;
    }
#endif

    ngx_cpuinfo();  //获得 ngx_cacheline_size 

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) { //获得rlmt
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed");
        return NGX_ERROR;
    }

    ngx_max_sockets = (ngx_int_t) rlmt.rlim_cur; //系统支持的最大socket数

#if (NGX_HAVE_INHERITED_NONBLOCK || NGX_HAVE_ACCEPT4)
    ngx_inherited_nonblocking = 1;
#else
    ngx_inherited_nonblocking = 0;
#endif

    tp = ngx_timeofday();
    srandom(((unsigned) ngx_pid << 16) ^ tp->sec ^ tp->msec); //随机种子

    return NGX_OK;
}


/*
	Nginx 版本，操作系统类型，发行版写入日志
*/
void
ngx_os_status(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0, NGINX_VER_BUILD);

#ifdef NGX_COMPILER
    ngx_log_error(NGX_LOG_NOTICE, log, 0, "built by " NGX_COMPILER);
#endif

#if (NGX_HAVE_OS_SPECIFIC_INIT)
    ngx_os_specific_status(log);
#endif

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "getrlimit(RLIMIT_NOFILE): %r:%r",
                  rlmt.rlim_cur, rlmt.rlim_max);
}


#if 0

ngx_int_t
ngx_posix_post_conf_init(ngx_log_t *log)
{
    ngx_fd_t  pp[2];

    if (pipe(pp) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "pipe() failed");
        return NGX_ERROR;
    }

    if (dup2(pp[1], STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, errno, "dup2(STDERR) failed");
        return NGX_ERROR;
    }

    if (pp[1] > STDERR_FILENO) {
        if (close(pp[1]) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, errno, "close() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

#endif
