#include <iostream>
#include <fstream>
#include <sstream>
#include <stdlib.h> 
#include <string.h> 

#include "net.h"

using namespace std;

struct dc *working_dc;

int main (int argc, char *argv[])
{
	working_dc = (dc *)malloc(sizeof(dc));
	working_dc->id = 1;
	working_dc->ip = strdup("173.240.5.1");
	working_dc->port = 443;


}