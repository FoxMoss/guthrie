#include "packets.pb.h"
#include <array>
#include <asio/ip/tcp.hpp>
#include <asio/post.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>

using asio::ip::tcp;

class Socket {
public:
  Socket(tcp::socket socket, std::function<void()> destroy_self)
      : socket(std::move(socket)), destroy_self(destroy_self) {}
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

  void do_read_body(uint32_t buf_size) {
    std::shared_ptr<uint8_t> buf = std::make_unique<uint8_t>(buf_size);
    asio::async_read(
        socket, asio::buffer(buf.get(), buf_size),
        [this, &buf, buf_size](std::error_code ec, std::size_t /*length*/) {
          if (!ec) {
            auto packet = UniversalPacket();
            if (!packet.ParseFromArray(buf.get(), buf_size)) {
              send_error("Failed to parse packet\n");
              return;
            }

            packet.payload_case();

            do_read_header();
          } else {
            schedule_destroy();
          }
        });
  }

  void send_error(std::string err) {
    auto error_packet = UniversalPacket();
    error_packet.error().se = err;
    schedule_destroy();
  }

  void schedule_destroy() { asio::post(socket.get_executor(), destroy_self); }

private:
  std::function<void()> destroy_self;
  std::array<uint8_t, sizeof(uint32_t)>
      header_buffer; // max packet size UINT32_MAX
};

class Server {
public:
  Server(asio::io_context &io_context, const tcp::endpoint &endpoint)
      : acceptor(io_context, endpoint), context(&io_context) {
    do_accept();
  }

private:
  void do_accept() {
    acceptor.async_accept([this](std::error_code ec, tcp::socket socket) {
      if (!ec) {
        std::function<void()> destroy_function =
            [this, socket_id = // must explicitly copy socket_id
                   socket_id_count]() {
              printf("destroyed client %zu\n", socket_id);
              socket_storage.erase(socket_id);
            };
        printf("created client %zu\n", socket_id_count);

        std::shared_ptr<Socket> socket_interface =
            std::make_shared<Socket>(std::move(socket), destroy_function);
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
};

int main(int argc, char *argv[]) {
  try {
    if (argc != 1) {
      printf("Usage: %s\n", argv[0]);
      return 1;
    }

    asio::io_context io_context;
    tcp::endpoint endpoint(tcp::v4(), 8448);
    Server s(io_context, endpoint);

    io_context.run();
  } catch (std::exception &e) {
    printf("%s: %s", argv[0], e.what());
  }

  return 0;
}
