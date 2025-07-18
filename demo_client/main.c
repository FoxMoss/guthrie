#include "guthrie.h"
#include <stdio.h>

int handle_unauth(GuthrieState *state, enum Status status) {
  if (status == STATUS_PACKET_AVAILABLE) {
    UniversalPacket *packet = guthrie_parse_packet(state);
    if (packet->payload_case == UNIVERSAL_PACKET__PAYLOAD_ERROR &&
        packet->error->error != NULL) {
      printf("\n---\n%s\n---\n", packet->error->error);
    }
  }

  char username[66]; // +1 for null term +1 newline
  printf("\nUsername: ");
  fgets(username, 66, stdin);
  username[65] = 0;
  char password[66];
  printf("Password: ");
  fgets(password, 66, stdin);
  password[65] = 0;

  if (guthrie_send_auth(state, username, password) == -1)
    return -1;
  return 0;
}

int main(int argc, char *argv[]) {
  OptionalGuthrieState op = guthrie_init();
  if (op.type == TYPE_ERROR) {
    printf("%s: %s\n", argv[0], op.data.error_str);
    return 1;
  }
  GuthrieState *state = op.data.state;
  guthrie_send_version(state);
  printf("Guthrie v%i.%i.%i.%i\n", VER_MAJOR, VER_MINOR, VER_PATCH, VER_EXTEN);

  enum {
    CLIENT_UNAUTHED,
    CLIENT_PRIVLAGED
  } client_level = CLIENT_UNAUTHED; // skiping preversioned

  while (true) {

    enum Status status;
    do {
      status = guthrie_async_read(state);
    } while (status == STATUS_READ);
    if (status == STATUS_EXIT)
      break;

    switch (client_level) {
    case CLIENT_UNAUTHED: {
      if (handle_unauth(state, status) == -1)
        goto goodbye;
      break;
    }
    case CLIENT_PRIVLAGED: {
      break;
    }
    }
  }

goodbye:
  printf("Goodbye!\n");

  guthrie_exit(state);
  return 0;
}
