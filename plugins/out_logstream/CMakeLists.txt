set(src
  logstream.c
  logstream_conf.c
  )

FLB_PLUGIN(out_logstream "${src}" "mk_core")
