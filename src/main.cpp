#include "packets.pb.h"
#include "pubsub.h"
#include <array>
#include <asio/ip/tcp.hpp>
#include <asio/post.hpp>
#include <asio/registered_buffer.hpp>
#include <asio/signal_set.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/write.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
  Socket(tcp::socket socket, std::function<void()> destroy_self, sqlite3 *mdb,
         PubSubManager<UniversalPacket> *pubsub, size_t socket_id_count)
      : socket(std::move(socket)), destroy_self(destroy_self), db(mdb),
        pubsub(pubsub), socket_id(socket_id_count) {}
  ~Socket() {
    if (!socket_user_id.has_value())
      return;
    pubsub->remove_listener(socket_user_id.value(), socket_id);
  }
  tcp::socket socket;

  void start() { do_read_header(); }
  void stop() { socket.close(); }
  void subscriber_receive(UniversalPacket packet) {
    send_packet(packet, false);
  }

private:
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

    case UniversalPacket::kAffirm: {
      if (!packet->has_affirm())
        return "Affirmation must be defined";
      if (!packet->affirm().has_type())
        return "Affirmation type must be defined";
      if (packet->affirm().type() < AFFIRM_LOGIN &&
          packet->affirm().type() > AFFIRM_MESSAGE)
        return "Invalid Affirmation Type";
      break;
    }
    case UniversalPacket::kError: {
      if (!packet->has_error())
        return "Error must be defined";
      if (!packet->error().has_error())
        return "Error message be defined";
      if (packet->error().error().size() > 1024)
        return "Error message must not exceed 1024 characters";
      break;
    }

    case UniversalPacket::kMsg: {
      if (!packet->has_msg())
        return "Message must be defined";

      if (!packet->msg().has_sender_identifier())
        return "Sender identifier must be defined";
      if (packet->msg().sender_identifier().size() != 64)
        return "Sender identifier must be exactly 64 characters";

      const auto &identifiers = packet->msg().identifiers();
      if (identifiers.size() < 1 || identifiers.size() > 256)
        return "Identifiers must contain between 1 and 256 items";

      for (const auto &id : identifiers) {
        if (id.size() != 64)
          return "Each identifier must be 64 characters";
      }

      if (packet->msg().has_channel_id() &&
          packet->msg().channel_id().size() != 64)
        return "Channel ID must be exactly 64 characters";

      if (!packet->msg().has_message())
        return "Message must be defined";
      if (packet->msg().message().size() > 1024)
        return "Message must not exceed 1024 characters";
      break;
    }
    default:
      return "Packet type not supported";
    }
    return {};
  }

  void do_read_body(uint32_t buf_size) {
    auto buf = std::shared_ptr<void>(malloc(buf_size), free);
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
              if (client_level != CLIENT_UNKNOWN)
                goto packet_parsing_error;

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
              if (client_level != CLIENT_UNAUTHED)
                goto packet_parsing_error;

              // auth errors should be nonfatal
              sqlite3_stmt *res;
              char *sql = "SELECT user_identifier, user_password FROM users "
                          "WHERE user_identifier = ?";

              if (sqlite3_prepare_v2(db, sql, -1, &res, NULL) != SQLITE_OK) {
                send_error("Sqlite3 failed", true);
                break;
              }
              sqlite3_bind_text(
                  res, 1, packet.login().user_identifier().c_str(),
                  packet.login().user_identifier().size(), SQLITE_TRANSIENT);

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
              sqlite3_finalize(res);

              // must affirm the client!
              auto affirmation_packet = UniversalPacket();
              affirmation_packet.mutable_affirm()->set_type(AFFIRM_LOGIN);
              send_packet(affirmation_packet, false);

              socket_user_id = packet.login().user_identifier();
              pubsub->listen(socket_user_id.value(), socket_id);

              // password matches so we good!
              client_level = CLIENT_PRIVLAGED;
              break;
            }
            case UniversalPacket::kMsg: {
              if (client_level != CLIENT_PRIVLAGED)
                goto packet_parsing_error;

              if (!socket_user_id.has_value() ||
                  packet.msg().sender_identifier() != socket_user_id.value())
                goto packet_parsing_error;

              auto affirmation_packet = UniversalPacket();
              affirmation_packet.mutable_affirm()->set_type(AFFIRM_MESSAGE);
              send_packet(affirmation_packet, false);

              for (size_t target_user_id_idex = 0;
                   target_user_id_idex < packet.msg().identifiers_size();
                   target_user_id_idex++) {
                pubsub->send(packet.msg().identifiers()[target_user_id_idex],
                             packet);
              }

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
    auto error_packet = UniversalPacket();
    error_packet.mutable_error()->set_error(err);
    send_packet(error_packet, kill_socket);
  }

  void send_packet(UniversalPacket packet, bool kill) {
    std::string buffer;
    packet.SerializeToString(&buffer);

    uint32_t size = buffer.size();
    uint8_t *combined_buffer = (uint8_t *)malloc(
        buffer.size() + sizeof(uint32_t)); // TODO: make this c++ly
    memcpy(combined_buffer, &size, sizeof(uint32_t));
    memcpy(combined_buffer + sizeof(uint32_t), buffer.c_str(), buffer.size());

    asio::async_write(
        socket, asio::buffer(combined_buffer, buffer.size() + sizeof(uint32_t)),
        [this, combined_buffer, kill](std::error_code ec,
                                      std::size_t /*length*/) {
          free(combined_buffer);
          if (kill)
            schedule_destroy();
        });
  }

  void schedule_destroy() { asio::post(socket.get_executor(), destroy_self); }

  enum {
    CLIENT_UNKNOWN,
    CLIENT_UNAUTHED,
    CLIENT_PRIVLAGED
  } client_level = CLIENT_UNKNOWN;
  std::function<void()> destroy_self;
  std::array<uint8_t, sizeof(uint32_t)>
      header_buffer; // max packet size UINT32_MAX

  sqlite3 *db;
  PubSubManager<UniversalPacket> *pubsub;

  size_t socket_id;
  std::optional<std::string> socket_user_id;
};

class Server : public PubSubManager<UniversalPacket> {
public:
  Server(asio::io_context &io_context, const tcp::endpoint &endpoint,
         sqlite3 *mdb)
      : acceptor(io_context, endpoint), context(&io_context), db(mdb),
        signals(io_context, SIGINT, SIGTERM),
        PubSubManager<UniversalPacket>(
            [this](size_t id, UniversalPacket packet) -> bool {
              if (!socket_storage.contains(id))
                return false;
              socket_storage[id]->subscriber_receive(packet);
              return true;
            }) {

    signals.async_wait([this](std::error_code /*ec*/, int /*signo*/) {
      acceptor.close();
      for (auto socket_obj : socket_storage) {
        socket_obj.second->stop();
      }
      context->stop();
    });

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

        std::shared_ptr<Socket> socket_interface = std::make_shared<Socket>(
            std::move(socket), destroy_function, db, this, socket_id_count);
        socket_storage[socket_id_count] = socket_interface;
        socket_interface->start();
        socket_id_count++;
        do_accept();
      } else {
        printf("hi!!\n");
      }
    });
  }

  size_t socket_id_count = 0;
  std::unordered_map<size_t, std::shared_ptr<Socket>> socket_storage;
  tcp::acceptor acceptor;
  asio::io_context
      *context; // might cause segfault should be a ptr to the main func's
  sqlite3 *db;
  asio::signal_set signals;
};

int main(int argc, char *argv[]) {
  sqlite3 *db = NULL;
  if (sqlite3_open("/var/db/guthrie.db", &db) != SQLITE_OK) {
    printf("%s: could not connect to sqlite database\n", argv[0]);
    return 1;
  }

  char *generate_db_sql =
      "CREATE TABLE 'users' ('id' integer PRIMARY KEY AUTOINCREMENT NOT NULL, "
      "'user_identifier' varchar, 'user_password' varchar, 'created_at' "
      "datetime(6) NOT NULL, 'updated_at' datetime(6) NOT NULL)"; // this should
                                                                  // be created
                                                                  // by rails

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

  google::protobuf::ShutdownProtobufLibrary();
  sqlite3_close(db);

  return 0;
}
