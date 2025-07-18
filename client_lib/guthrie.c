#include "guthrie.h"
#include "packets.pb-c.h"
#include <asm-generic/errno-base.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

OptionalGuthrieState guthrie_init() {
  signal(SIGPIPE, SIG_IGN);
  int client_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (client_fd == -1)
    return (OptionalGuthrieState){TYPE_ERROR,
                                  {.error_str = "Failed to create socket"}};

  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(8448);

  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) != 1)
    return (OptionalGuthrieState){TYPE_ERROR, {.error_str = "Failed find ip"}};

  if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0)
    return (OptionalGuthrieState){TYPE_ERROR,
                                  {.error_str = "Failed to connect"}};

  if (fcntl(client_fd, F_SETFL, O_NONBLOCK) == -1)
    return (OptionalGuthrieState){
        TYPE_ERROR, {.error_str = "Failed to make socket non blocking"}};

  GuthrieState *ret = (GuthrieState *)malloc(sizeof(GuthrieState));
  ret->file_descriptor = client_fd;
  ret->reading_sate = READING_HEADER;
  ret->buffer_cursor = 0;
  ret->buffer_size = sizeof(uint32_t);
  ret->buffer = malloc(ret->buffer_size);

  ret->packet = NULL;
  return (OptionalGuthrieState){TYPE_GUTHRIE, {.state = ret}};
}

enum Status guthrie_async_read(GuthrieState *state) {
  if (state->packet != NULL) {
    universal_packet__free_unpacked(state->packet, NULL);
    state->packet = NULL;
  }

  if (state->buffer_cursor == state->buffer_size &&
      state->reading_sate == READING_HEADER) {
    state->reading_sate = READING_BUFFER;
    state->buffer_size = *(uint32_t *)state->buffer;
    state->buffer_cursor = 0;
    state->buffer = realloc(state->buffer, state->buffer_size);
  } else if (state->buffer_cursor == state->buffer_size &&
             state->reading_sate == READING_BUFFER) {
    state->reading_sate = READING_HEADER;
    state->buffer_cursor = 0;
    state->buffer_size = sizeof(uint32_t);
    state->buffer = realloc(state->buffer, sizeof(uint32_t));
  }

  int new_bytes =
      read(state->file_descriptor, state->buffer + state->buffer_cursor,
           state->buffer_size - state->buffer_cursor);
  if (new_bytes == -1 && (errno != EAGAIN || errno != EWOULDBLOCK)) {
    return STATUS_EXIT;
  } else if (new_bytes == -1) {
    return STATUS_NO_DATA;
  }

  state->buffer_cursor += new_bytes;
  if (state->buffer_cursor == state->buffer_size &&
      state->reading_sate == READING_BUFFER) {
    state->packet =
        universal_packet__unpack(NULL, state->buffer_size, state->buffer);
    return STATUS_PACKET_AVAILABLE;
  }
  return STATUS_READ;
}

UniversalPacket *guthrie_parse_packet(GuthrieState *state) {
  return state->packet;
}

void guthrie_send_version(GuthrieState *state) {
  UniversalPacket universal = UNIVERSAL_PACKET__INIT;
  VersionPacket version = VERSION_PACKET__INIT;

  version.has_major_ver = 1;
  version.major_ver = VER_MAJOR;

  version.has_minor_ver = 1;
  version.minor_ver = VER_MINOR;

  version.has_patch_ver = 1;
  version.patch_ver = VER_PATCH;

  version.has_protocol_extension = true;
  version.protocol_extension = VER_EXTEN;

  universal.payload_case = UNIVERSAL_PACKET__PAYLOAD_VERSION;
  universal.version = &version;

  size_t buffer_size = universal_packet__get_packed_size(&universal);
  void *buffer = malloc(buffer_size);
  universal_packet__pack(&universal, buffer);

  uint32_t small_buffer_size = buffer_size;
  write(state->file_descriptor, &small_buffer_size, sizeof(uint32_t));
  write(state->file_descriptor, buffer, buffer_size);

  free(buffer);
}
int guthrie_send_auth(GuthrieState *state, char *user_identifier,
                      char *user_password) {
  UniversalPacket universal = UNIVERSAL_PACKET__INIT;
  LoginPacket login = LOGIN_PACKET__INIT;

  login.user_identifier = user_identifier;
  login.user_password = user_password;

  universal.payload_case = UNIVERSAL_PACKET__PAYLOAD_LOGIN;
  universal.login = &login;

  size_t buffer_size = universal_packet__get_packed_size(&universal);
  void *buffer = malloc(buffer_size);
  universal_packet__pack(&universal, buffer);

  uint32_t small_buffer_size = buffer_size;
  int status = -1;
  int err = EAGAIN;
  while (status == -1 && err == EAGAIN) {
    status =
        write(state->file_descriptor, &small_buffer_size, sizeof(uint32_t));
    err = errno;
  }
  if (status == -1) {
    free(buffer);
    return -1;
  }

  status = -1;
  err = EAGAIN;

  while (status == -1 && err == EAGAIN) {
    status = write(state->file_descriptor, buffer, buffer_size);
    err = errno;
  }
  if (status == -1) {
    free(buffer);
    return -1;
  }

  free(buffer);
  return 0;
}

void guthrie_exit(GuthrieState *state) {
  if (state->packet != NULL)
    universal_packet__free_unpacked(state->packet, NULL);

  close(state->file_descriptor);
  free(state->buffer);
  free(state);
}
