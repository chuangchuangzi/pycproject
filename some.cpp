#include <stdio.h>
int main(int argc, char **argv) {
  short a;
  char b;
  int c;
  float f;
  for (int i = 1; i < argc; ++i) {
    printf("%d%d%d%f", a, b, c, f);
  }
}