#include "guthrie.h"
#include "packets.pb-c.h"
#include <stdio.h>

int handle_unauth(GuthrieState *state) {

  char username[66]; // +1 for null term +1 newline
  printf("\nUsername: ");
  fgets(username, 66, stdin);
  username[64] = 0;
  char password[66];
  printf("Password: ");
  fgets(password, 66, stdin);
  password[64] = 0;

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
  printf("Guthrie v%i.%i.%i ^%i\n", VER_MAJOR, VER_MINOR, VER_PATCH, VER_EXTEN);

  enum {
    CLIENT_UNAUTHED,
    CLIENT_PRIVLAGED
  } client_level = CLIENT_UNAUTHED; // skiping preversioned

  while (true) {

    if (guthrie_async_read(state) == STATUS_EXIT)
      break;

    switch (client_level) {
    case CLIENT_UNAUTHED: {
      if (handle_unauth(state) == -1)
        goto goodbye;

      do {
        enum Status status = guthrie_async_read(state);
        if (status == STATUS_PACKET_AVAILABLE) {
          UniversalPacket *packet = guthrie_parse_packet(state);
          if (packet->payload_case == UNIVERSAL_PACKET__PAYLOAD_AFFIRM &&
              packet->affirm->type == AFFIRMATION_TYPE__AFFIRM_LOGIN) {
            client_level = CLIENT_PRIVLAGED;
            printf("Logged in!\n");
          }

          if (packet->payload_case == UNIVERSAL_PACKET__PAYLOAD_ERROR)
            printf("\n---\n%s\n---\n", packet->error->error);
          break;
        } else if (status == STATUS_EXIT) {
          break;
        }

      } while (true);
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
