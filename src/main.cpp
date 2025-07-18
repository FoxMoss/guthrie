#include "packets.pb.h"
#include <array>
#include <asio/ip/tcp.hpp>
#include <asio/post.hpp>
#include <asio/registered_buffer.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/write.hpp>
#include <buf/validate/validator.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <functional>
#include <memory>
#include <sqlite3.h>
#include <string>
#include <unordered_map>
#include <utility>

#define VER_MAJOR 0
#define VER_MINOR 1
#define VER_PATCH 0
#define VER_EXTEN 0

using asio::ip::tcp;

class Socket {
public:
  Socket(tcp::socket socket, std::function<void()> destroy_self, sqlite3 *db)
      : socket(std::move(socket)), destroy_self(destroy_self), db(db) {}
  tcp::socket socket;

  void start() { do_read_header(); }

  void do_read_header() {
    // async read will always read the specified size
    asio::async_read(socket,
                     asio::buffer(header_buffer.data(), header_buffer.size()),
                     [this](std::error_code ec, std::size_t /*length*/) {
                       printf("read\n");

                       uint32_t body_size = *(uint32_t *)header_buffer.data();
                       if (!ec) {
                         do_read_body(body_size);
                       } else {
                         schedule_destroy();
                       }
                     });
  }

  std::optional<std::string> validate_packet(UniversalPacket *packet) {
    switch (packet->payload_case()) {
    case UniversalPacket::kVersion: {
      if (!packet->has_version())
        return "Version must be defined";
      if (!packet->version().has_major_ver())
        return "Major Version must be defined";
      if (!packet->version().has_minor_ver())
        return "Minor Version must be defined";
      if (!packet->version().has_patch_ver())
        return "Patch Version must be defined";
      if (!packet->version().has_protocol_extension())
        return "Protocol Extension must be defined";
      break;
    }
    case UniversalPacket::kLogin: {
      if (!packet->has_login())
        return "Login must be defined";
      if (!packet->login().has_user_identifier())
        return "User Identifier must be defined";
      if (packet->login().user_identifier().size() != 64)
        return "Identifier must be exactly 64 characters";
      if (!packet->login().has_user_password())
        return "User Password must be defined";
      if (packet->login().user_password().size() != 64)
        return "Password must be exactly 64 characters";

      break;
    }
    default:
      return "Packet type not supported";
    }
    return {};
  }

  void do_read_body(uint32_t buf_size) {
    std::shared_ptr<uint8_t> buf = std::make_unique<uint8_t>(buf_size);
    asio::async_read(
        socket, asio::buffer(buf.get(), buf_size),
        [this, buf, buf_size](std::error_code ec, std::size_t /*length*/) {
          if (!ec) {
            auto packet = UniversalPacket();

            if (!packet.ParseFromArray(buf.get(), buf_size)) {
              send_error("Failed to parse packet", true);
              return;
            }

            auto validation = validate_packet(&packet);
            if (validation.has_value()) {
              send_error(validation.value(), false);
              goto continue_reading_packets;
            }

            switch (packet.payload_case()) {
            case UniversalPacket::kVersion: {
              if (client_level != CLIENT_UNKNOWN) {
                goto packet_parsing_error;
              }
              printf("Client version v%i.%i.%i#%i\n",
                     packet.version().major_ver(), packet.version().minor_ver(),
                     packet.version().patch_ver(),
                     packet.version().protocol_extension());

              if (packet.version().major_ver() != VER_MAJOR ||
                  packet.version().minor_ver() != VER_MINOR ||
                  packet.version().patch_ver() != VER_PATCH ||
                  packet.version().protocol_extension() != VER_EXTEN) {
                send_error("Incompatible version", true);
                return;
              }

              // all good then!
              client_level = CLIENT_UNAUTHED;

              break;
            }
            case UniversalPacket::kLogin: {
              if (client_level != CLIENT_UNAUTHED) {
                goto packet_parsing_error;
              }

              // auth errors should be nonfatal
              // TODO: implement me!
              sqlite3_stmt *res;
              char *sql = "SELECT user_identifier, user_password FROM users "
                          "WHERE user_identifier = ?";

              if (sqlite3_prepare_v2(db, sql, -1, &res, 0) != SQLITE_OK) {
                send_error("Sqlite3 failed", true);
                break;
              }
              sqlite3_bind_text(
                  res, 0, packet.login().user_identifier().c_str(),
                  packet.login().user_identifier().size(), SQLITE_STATIC);

              int step = sqlite3_step(res);

              if (step != SQLITE_ROW) {
                send_error("Could not find user", false);
                sqlite3_finalize(res);
                break;
              }
              auto target_password = sqlite3_column_text(res, 1);
              if (strncmp((char *)target_password,
                          packet.login().user_password().c_str(), 64) != 0) {
                send_error("Password does not match", false);
                sqlite3_finalize(res);
                break;
              }

              // password matches so we good!
              client_level = CLIENT_PRIVLAGED;

              break;
            }

            case UniversalPacket::PAYLOAD_NOT_SET:
            default: {
            packet_parsing_error:
              send_error("Packet invalid", true);
              return;
            }
            }

          continue_reading_packets:
            do_read_header();
          } else {
            schedule_destroy();
          }
        });
  }

  void send_error(std::string err, bool kill_socket) {
    printf("%s\n", err.c_str());
    if (kill_socket) {
      schedule_destroy();
    } else {
      auto error_packet = UniversalPacket();
      ErrorPacket *error = new ErrorPacket;
      error->set_error(err);
      error_packet.set_allocated_error(error);
      send_packet(error_packet);
    }
  }

  void send_packet(UniversalPacket packet) {
    std::string buffer;
    packet.SerializeToString(&buffer);
    size_t size = buffer.size();
    asio::async_write(
        socket, asio::buffer(&size, sizeof(uint32_t)),
        [this, buffer](std::error_code ec, std::size_t /*length*/) {
          asio::async_write(
              socket, asio::buffer(buffer.data(), buffer.size()),
              [this](std::error_code ec, std::size_t /*length*/) {});
        });
  }

  void schedule_destroy() { asio::post(socket.get_executor(), destroy_self); }

private:
  enum {
    CLIENT_UNKNOWN,
    CLIENT_UNAUTHED,
    CLIENT_PRIVLAGED
  } client_level = CLIENT_UNKNOWN;
  std::function<void()> destroy_self;
  std::array<uint8_t, sizeof(uint32_t)>
      header_buffer; // max packet size UINT32_MAX
  sqlite3 *db;
};

class Server {
public:
  Server(asio::io_context &io_context, const tcp::endpoint &endpoint,
         sqlite3 *db)
      : acceptor(io_context, endpoint), context(&io_context), db(db) {
    do_accept();
  }

private:
  void do_accept() {
    acceptor.async_accept([this](std::error_code ec, tcp::socket socket) {
      if (!ec) {
        std::function<void()> destroy_function =
            [this, socket_id = // must explicitly copy socket_id
                   socket_id_count]() {
              if (socket_storage.contains(socket_id)) {
                printf("destroyed client %zu\n", socket_id);
                socket_storage.erase(socket_id);
              }
            };
        printf("created client %zu\n", socket_id_count);

        std::shared_ptr<Socket> socket_interface =
            std::make_shared<Socket>(std::move(socket), destroy_function, db);
        socket_storage[socket_id_count] = socket_interface;
        socket_interface->start();
        socket_id_count++;
      }

      do_accept();
    });
  }

  size_t socket_id_count = 0;
  std::unordered_map<size_t, std::shared_ptr<Socket>> socket_storage;
  tcp::acceptor acceptor;
  asio::io_context
      *context; // might cause segfault should be a ptr to the main func's
  sqlite3 *db;
};

int main(int argc, char *argv[]) {
  sqlite3 *db;
  sqlite3_open("data.db", &db);
  char *generate_db_sql = "CREATE TABLE IF NOT EXISTS users ("
                          "user_identifier TEXT NOT NULL,"
                          "user_password TEXT NOT NULL,"
                          "date_created DATETIME DEFAULT CURRENT_TIMESTAMP,"
                          "PRIMARY KEY (user_identifier)"
                          ")";
  char *error_msg;
  if (sqlite3_exec(db, generate_db_sql, NULL, 0, &error_msg) != SQLITE_OK) {
    printf("%s: %s\n", argv[0], error_msg);
    sqlite3_close(db);
    return 1;
  }

  try {
    if (argc != 1) {
      printf("Usage: %s\n", argv[0]);
      return 1;
    }

    printf("guthrie server listening on port %i\n", 8448);

    asio::io_context io_context;
    tcp::endpoint endpoint(tcp::v4(), 8448);
    Server s(io_context, endpoint, db);

    io_context.run();
  } catch (std::exception &e) {
    printf("%s: %s", argv[0], e.what());
  }
  sqlite3_close(db);

  return 0;
}
