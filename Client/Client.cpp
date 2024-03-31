#include <iostream>
#include <boost/asio.hpp>
#include <codecvt>
#include <locale>
#include <fcntl.h>
#include <io.h>
#include <fstream>
#include <filesystem>
#include <winsock2.h>
#include <Windows.h>
#include <vector>
#include <boost/asio/thread_pool.hpp>
#include <openssl/sha.h>
#include <openssl/evp.h>

using boost::asio::ip::tcp;

class Client {
public:
    Client(boost::asio::io_context& io_context, short port)
        : socket_(std::make_shared<tcp::socket>(io_context)), pool_(4) {
    }

    void connect_to_server(const std::string& server_ip, short port) {
        try {
            //socket_ = std::make_shared<tcp::socket>(io_context);
            socket_->connect(tcp::endpoint(boost::asio::ip::address::from_string(server_ip), port));
            connected_ = true;
            std::wcout << L"Connected to server successfully!" << std::endl;
        }
        catch (const boost::system::system_error& ex) {
            std::wcerr << L"Failed to connect to server: " << ex.what() << std::endl;
            exit(1);
        }
    }

    void interact() {
        std::thread write_thread(&Client::do_write, this);
        write_thread.join();
    }

    void do_read() {
        while (true) {
            boost::asio::streambuf buffer;
            boost::system::error_code error;
            boost::asio::read_until(*socket_, buffer, '\n', error);
            if (!error) {
                std::istream is(&buffer);
                std::string line;
                std::getline(is, line);
                std::cout << "Received from server: " << line << std::endl;
            }
            else {
                std::cerr << "Failed to read from server: " << error.message() << std::endl;
                break;
            }
        }
    }

    void do_write() {

        while (true) {
            std::wcout << L"Enter message: ";
            std::getline(std::wcin, message_);
            handle_message();
        }
    }

    void send_text(std::string utf8_message) {
        if (connected_) {
            boost::asio::async_write(*socket_, boost::asio::buffer(utf8_message),
                [this](boost::system::error_code ec, std::size_t /*length*/) {
                    if (ec) {
                        std::wstring wide_message = string_to_wstring(ec.message());
                        std::wcerr << L"Failed to write to server: " << wide_message << std::endl;
                    }
                });
        }
        else {
            std::wcout << L"Please connect server before" << std::endl;
            exit(1);
        }
    }

    void handle_send_file(const std::wstring& path, std::size_t buffer_size) {
        if (connected_) {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                std::wcerr << L"Failed to open file: " << path << std::endl;
                return;
            }

            file.seekg(0, std::ios::end);
            std::size_t file_size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::filesystem::path fs_path = std::filesystem::path(path);
            std::wstring filename = fs_path.filename().wstring();

            std::string hashed_file = hash_input("file", wstring_to_string(path));

            std::string message = "sendfile " + std::string(filename.begin(), filename.end()) + " " + std::to_string(file_size) + " " + std::to_string(buffer_size) + " " + hashed_file + "\n";
            boost::asio::async_write(*socket_, boost::asio::buffer(message),
                [this](boost::system::error_code ec, std::size_t /*length*/) {
                    if (!ec) {
                        std::wcout << L"Message sent successfully.\n";
                    }
                    else {
                        std::wcerr << L"Failed to send message: " << string_to_wstring(ec.message()) << "\n";
                    }
                });

            std::vector<char> buffer(buffer_size);

            while (file.read(buffer.data(), buffer_size) || file.gcount()) {
                std::size_t bytes_read = file.gcount();
                boost::asio::async_write(*socket_, boost::asio::buffer(buffer.data(), bytes_read),
                    [this](boost::system::error_code ec, std::size_t /*length*/) {
                        if (ec) {
                            std::wstring wide_message = string_to_wstring(ec.message());
                            std::wcerr << L"Failed to write to server: " << wide_message << std::endl;
                        }
                    });
            }
        }
        else {
            std::wcout << L"Please connect server before" << std::endl;
            exit(1);
        }
    }

    void handle_send_text(std::string utf8_message) {
        if (connected_) {
            std::string hashed_message = hash_input("text", utf8_message);

            std::string message_size = std::to_string(utf8_message.size());
            send_text("sendtext " + message_size + " " + hashed_message + "\n");

            send_text(utf8_message);
        }
        else {
            std::wcout << L"Please connect to the server before" << std::endl;
            std::exit(1);
        }
    }

    void handle_message() {
        std::wistringstream iss(message_);
        std::wstring command;
        std::getline(iss, command, L' ');  // Get the first word from the message
        std::transform(command.begin(), command.end(), command.begin(), ::tolower);  // Convert the command to lowercase

        if (!command.empty()) {
            if (command == L"sendtext") {
                std::wstring utf16_message;
                std::getline(iss, utf16_message);
                std::string utf8_message = wstring_to_string(utf16_message);
                boost::asio::post(pool_, [this, utf8_message]() {handle_send_text(utf8_message); });
            }
            else if (command == L"sendfile") {
                std::wstring path;
                if (!std::getline(iss, path, L' ')) {
                    std::wcerr << L"Failed to read path" << std::endl;
                    return;
                }

                std::wstring buffer_size_str;
                if (!std::getline(iss, buffer_size_str)) {
                    std::wcerr << L"Failed to read buffer size" << std::endl;
                    return;
                }

                try {
                    int buffer_size = std::stoi(buffer_size_str);
                    boost::asio::post(pool_, [this, path, buffer_size]() {handle_send_file(path, buffer_size); });
                }
                catch (const std::invalid_argument& e) {
                    std::wcerr << L"Invalid buffer size: " << buffer_size_str << std::endl;
                }
                catch (const std::out_of_range& e) {
                    std::wcerr << L"Buffer size out of range: " << buffer_size_str << std::endl;
                }
            }
            else if (command == L"senddata") {
                std::wstring server_ip_wstr;
                std::getline(iss, server_ip_wstr, L':');
                std::string server_ip = wstring_to_string(server_ip_wstr);

                std::wstring port_wstr;
                std::getline(iss, port_wstr);
                short port = std::stoi(port_wstr);

                connect_to_server(server_ip, port);
            }
            else if (command == L"receivedata") {
                std::string utf8_message = wstring_to_string(message_);
                utf8_message += "\n";
                boost::asio::post(pool_, [this, utf8_message]() {send_text(utf8_message); });
            }
            else {
                std::wcerr << L"Invalid command" << std::endl;
            }
        }
    }

    // support function
    std::string wstring_to_string(const std::wstring& wstr)
    {
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string str_to(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &str_to[0], size_needed, NULL, NULL);
        return str_to;
    }

    std::wstring string_to_wstring(const std::string& str)
    {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
        std::wstring wstr_to(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr_to[0], size_needed);
        return wstr_to;
    }

    std::string hash_input(const std::string& type, const std::string& input) {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL) {
            throw std::runtime_error("Failed to create EVP_MD_CTX");
        }

        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to initialize EVP_MD_CTX with SHA-256");
        }

        std::ostringstream oss;

        if (type == "text") {
            if (EVP_DigestUpdate(mdctx, input.c_str(), input.size()) != 1) {
                EVP_MD_CTX_free(mdctx);
                throw std::runtime_error("Failed to update hash with data");
            }
        }
        else if (type == "file") {
            std::ifstream file(input, std::ios::binary);
            if (!file) {
                EVP_MD_CTX_free(mdctx);
                return ""; // File not found or cannot be opened
            }

            const size_t buffer_size = 4096;
            char buffer[buffer_size];
            while (file.read(buffer, buffer_size)) {
                if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    throw std::runtime_error("Failed to update hash with data");
                }
            }
        }

        std::vector<unsigned char> hash(EVP_MD_size(EVP_sha256()));
        unsigned int len = 0;
        if (EVP_DigestFinal_ex(mdctx, hash.data(), &len) != 1) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to finalize hash");
        }

        for (int i = 0; i < hash.size(); i++) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        EVP_MD_CTX_free(mdctx);
        return oss.str();
    }

private:
    std::shared_ptr<tcp::socket> socket_;
    boost::asio::streambuf buffer_;
    std::wstring message_;
    boost::asio::thread_pool pool_;
    boost::asio::io_context io_context_;
    bool connected_;
};

int main() {
    try {
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);

        std::wcout << L"CLIENT" << std::endl;

        boost::asio::io_context io_context;
        Client client(io_context, 8888);

        // Set up communication with the server
        client.interact();

        io_context.run();
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}