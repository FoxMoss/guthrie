#include "guthrie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *user_identifier = NULL;
int handle_unauth(GuthrieState *state) {

  char username[66]; // +1 for null term +1 newline
  printf("Username: \n");
  fgets(username, 66, stdin);
  username[64] = 0;
  char password[66];
  printf("Password: \n");
  fgets(password, 66, stdin);
  password[64] = 0;

  user_identifier = malloc(65);
  memcpy(user_identifier, username, 65);

  if (guthrie_send_auth(state, username, password) == -1)
    return -1;
  return 0;
}

int main(int argc, char *argv[]) {
  OptionalGuthrieState op = guthrie_init("205.185.125.167", 8448);
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

      enum Status status = guthrie_async_read(state);
      if (status == STATUS_PACKET_AVAILABLE) {
        UniversalPacket *packet = guthrie_parse_packet(state);
        if (packet->payload_case == UNIVERSAL_PACKET__PAYLOAD_AFFIRM &&
            packet->affirm->type == AFFIRMATION_TYPE__AFFIRM_MESSAGE) {
          printf("Message affirmed\n");
        }

        if (packet->payload_case == UNIVERSAL_PACKET__PAYLOAD_MSG)
          printf("\n--- From %s\n%s\n---\n", packet->msg->sender_identifier,
                 packet->msg->message);

        if (packet->payload_case == UNIVERSAL_PACKET__PAYLOAD_ERROR)
          printf("\n---\n%s\n---\n", packet->error->error);

        break;
      } else if (status == STATUS_EXIT) {
        break;
      }

      char op[3];
      fgets(op, 3, stdin);
      switch (op[0]) {
      case 's': {
        char recipient_identifier[66]; // +1 for null term +1 newline
        printf("Send to: \n");
        fgets(recipient_identifier, 66, stdin);
        recipient_identifier[64] = 0;
        char *recipient_identifier_ptr = (char *)(&recipient_identifier[0]);

        char body[258];
        printf("Message: \n");
        fgets(body, 258, stdin);
        body[256] = 0;
        guthrie_send_message(state, user_identifier, NULL,
                             &recipient_identifier_ptr, 1, body);
        break;
      }
      case 'c':
      default: {
        printf("Skipping!\n");
        break;
      }
      }
      break;
    }
    }
  }

goodbye:
  printf("Goodbye!\n");

  guthrie_exit(state);
  if (user_identifier != NULL)
    free(user_identifier);
  return 0;
}
