/*
 * simplegram.cpp
 *
 *  Created on: 2014/03/12
 *      Author: fernancoder
 */

#include "include.h"
#include "net.h"

struct session *working_sesion;



int rpc_execute (struct connection *c, int op, int len);
int rpc_becomes_ready (struct connection *c);
int rpc_close (struct connection *c);

struct connection_methods auth_methods = {
  rpc_becomes_ready,
  rpc_close,
  rpc_execute
};

int main (int argc, char *argv[])
{
  struct dc *working_dc = (dc *)malloc(sizeof(dc));
  working_dc->id = 1;
  working_dc->ip = strdup("173.240.5.1");
  working_dc->port = 443;


  struct session *working_sesion = (session *)malloc(sizeof(session));
  RAND_pseudo_bytes ((unsigned char *) &working_sesion->session_id, 8);
  working_sesion->dc = working_dc;
  working_sesion->c = create_connection (working_dc->ip, working_dc->port, working_sesion, &auth_methods);
  if (!working_sesion->c) {
    cout << "Can not create connection to DC. Is network down?" << endl;
    exit (1);
  }

  cout << "Connection created!!!" << endl;
}


