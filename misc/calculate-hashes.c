#include "../MiniCRT/misc.h"
#include "../MiniCRT/read.h"
#include "../MiniCRT/CRT.h"

void main() {
	printf("hash is %u", crt_hash("__gmon_start__"));
}
