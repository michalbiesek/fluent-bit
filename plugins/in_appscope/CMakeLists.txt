set(src
  appscope_conf.c
  appscope_conn.c
  appscope_prot.c
  appscope_server.c
  appscope.c)

FLB_PLUGIN(in_appscope "${src}" "")
