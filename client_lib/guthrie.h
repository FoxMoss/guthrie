#pragma once
#include <../gen/packets.pb-c.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#define VER_MAJOR 0
#define VER_MINOR 1
#define VER_PATCH 0
#define VER_EXTEN 0

typedef struct {
  int file_descriptor;

  uint32_t buffer_size;
  uint32_t buffer_cursor;
  uint8_t *buffer;
  UniversalPacket *packet;
  enum { READING_HEADER, READING_BUFFER } reading_sate;
} GuthrieState;

typedef struct {
  enum Type {
    TYPE_ERROR,
    TYPE_GUTHRIE,
  } type;
  union {
    GuthrieState *state;
    char *error_str;
  } data;
} OptionalGuthrieState;

OptionalGuthrieState guthrie_init();

enum Status {
  STATUS_EXIT,
  STATUS_READ,
  STATUS_NO_DATA,
  STATUS_PACKET_AVAILABLE,
};
/**
 * Read any data available from the file descriptor. Call this funcion as a part
 * of your event loop to stay up to date with incoming packets. If the function
 * returns 1 it means a packet is available to be parsed. If false the socket
 * may be sending in data but it is not fully formed. If the function returns -1
 * this means the socket is no longer available.
 */
enum Status guthrie_async_read(GuthrieState *state);
/**
 * Returns NULL if not available. Check result, and only use value of
 * guthrie_async_read returned true.
 */
UniversalPacket *guthrie_parse_packet(GuthrieState *state);
void guthrie_send_version(GuthrieState *state);
int guthrie_send_auth(GuthrieState *state, char *user_identifier,
                      char *user_password);
void guthrie_exit(GuthrieState *state);
