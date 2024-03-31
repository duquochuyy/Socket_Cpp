#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/thread_pool.hpp>
#include <codecvt>
#include <locale>
#include <fcntl.h>
#include <io.h>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <winsock2.h>
#include <vector>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <iomanip>

using boost::asio::ip::tcp;

class Server {
public:
    Server(boost::asio::io_context& io_context, short port)
        : io_context_(io_context),
        acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
        pool_(10) {
        do_accept();
    }

private:
    void do_accept() {
        auto socket = std::make_shared<tcp::socket>(io_context_);
        acceptor_.async_accept(*socket, [this, socket](boost::system::error_code ec) {
            if (!ec) {
                std::wcout << L"Client connected from " << string_to_wstring(socket->remote_endpoint().address().to_string())
                    << L":" << socket->remote_endpoint().port() << std::endl;
                //boost::asio::post(pool_, [this, socket]() { handle_connection(socket); });
                handle_connection(socket);
            }
            else {
                std::wcout << L"Error: " << string_to_wstring(ec.message()) << std::endl;
            }
            // Accept the next connection
            do_accept();
            });
    }

    void send_message(std::shared_ptr<tcp::socket> socket, const std::string& message) {
        boost::asio::async_write(*socket, boost::asio::buffer(message + "\n"),
            [this](boost::system::error_code ec, std::size_t /*length*/) {
                if (ec) {
                    std::wstring wide_message = string_to_wstring(ec.message());
                    std::wcerr << L"Failed to send message to client: " << wide_message << std::endl;
                }
            });
    }

    void handle_receive_file(std::shared_ptr<tcp::socket> socket, std::string info) {
        std::wstring utf16_info = string_to_wstring(info);
        std::wcout << L"Received from client: " << utf16_info << std::endl;
        std::wistringstream iss(utf16_info);
        std::wstring filename;
        std::wstring file_size_str;
        std::wstring buffer_size_str;
        std::wstring hashed_file;
        std::getline(iss, filename, L' ');
        std::getline(iss, file_size_str, L' ');
        std::getline(iss, buffer_size_str, L' ');
        std::getline(iss, hashed_file);
        int buffer_size = std::stoi(buffer_size_str);
        std::size_t file_size = std::stoull(file_size_str);

        std::wcout << L"Received file: " << filename << L", size: " << file_size << std::endl;

        std::ofstream file(path_to_store + filename, std::ios::binary);
        if (!file) {
            std::wcerr << L"Failed to open file: " << filename << std::endl;
            return;
        }

        std::vector<char> buffer(buffer_size);
        std::size_t bytes_received = 0;

        while (bytes_received < file_size)
        {
            boost::system::error_code error;
            size_t length = socket->read_some(boost::asio::buffer(buffer), error);

            if (!error)
            {
                file.write(buffer.data(), length);
                bytes_received += length;
            }
            else
            {
                std::wcout << L"Error in read_some: " << string_to_wstring(error.message()) << std::endl;
                break;
            }
        }

        if (bytes_received = file_size) {
            file.close();

            std::string hash_file_receive = hash_input("file", wstring_to_string(path_to_store + filename));

            if (hash_file_receive == wstring_to_string(hashed_file)) {
                std::wcout << L"File integrity check passed!" << std::endl;
            }
            else {
                std::wcout << L"File has been altered!" << std::endl;
            }

            std::wcout << L"Receive file success!" << std::endl;
        }
    }

    void handle_receive_text(std::shared_ptr<tcp::socket> socket, std::string message) {
        //std::wcout << "Text from client: " << string_to_wstring(message) << std::endl;
    
        std::wstring utf16_info = string_to_wstring(message);

        std::wistringstream iss(utf16_info);
        std::wstring text_size_str;
        std::wstring hashed_text;
        int text_size;
        try
        {
            std::getline(iss, text_size_str, L' ');
            std::getline(iss, hashed_text);
            text_size = std::stoi(text_size_str);
        }
        catch (const std::exception&)
        {
            std::wcerr << L"Failed to read text" << std::endl;
            return;
        }



        // Create a buffer with the appropriate size
        std::vector<char> buffer(text_size);
        boost::system::error_code error;

        // Read the message from the socket
        size_t length = socket->read_some(boost::asio::buffer(buffer), error);
 
        if (error) {
            std::wstring wide_message = string_to_wstring(error.message());
            std::wcerr << L"Failed to read from client: " << wide_message << std::endl;
            return;
        }

        std::string message_text(buffer.data(), length);

        // Hash the received message
        std::string hashed_received_message = hash_input("text", message_text);

        // Compare the hash of the received message with the hash sent by the client
        if (hashed_received_message == wstring_to_string(hashed_text)) {
            std::wcout << L"Message from client: " << string_to_wstring(message_text) << std::endl;
        }
        else {
            std::wcerr << L"Message has been altered!" << std::endl;
        }
    }

    void handle_set_path(std::string message) {
        std::wstring utf16_info = string_to_wstring(message);
        std::wstring out;
        std::wstring path;
        std::wistringstream iss(utf16_info);
        std::getline(iss, out, L' ');
        std::getline(iss, path);
        if (!path.empty() && path.back() != L'\\') {
            path += L'\\';
        }
        path_to_store = path;
    }

    // handle message from client
    void handle_message(std::shared_ptr<tcp::socket> socket, std::string utf8_message) {

        std::string message = utf8_message;
        std::istringstream iss(message);
        std::string command;
        std::getline(iss, command, ' ');
        std::transform(command.begin(), command.end(), command.begin(), ::tolower); 

        if (!command.empty()) {
            if (command == "sendtext") {
                std::string remaining_message;
                std::getline(iss, remaining_message);
                //boost::asio::post(pool_, [this, remaining_message]() { handle_receive_text(remaining_message); });
                handle_receive_text(socket, remaining_message);
            }
            else if (command == "sendfile") {
                std::string remaining_message;
                std::getline(iss, remaining_message); 
                //boost::asio::post(pool_, [this, socket, remaining_message]() {handle_receive_file(socket, remaining_message); });
                handle_receive_file(socket, remaining_message);
            }
            else if (command == "receivedata") {
                std::string remaining_message;
                std::getline(iss, remaining_message);
                //boost::asio::post(pool_, [this, socket, remaining_message]() {handle_set_path(remaining_message); });
                handle_set_path(remaining_message);
            }
            else {
                std::wcout << L"Error format message" << std::endl;
            }
        }
    }

    // get messaage from client
    void handle_connection(std::shared_ptr<tcp::socket> socket) {
        auto buffer = std::make_shared<boost::asio::streambuf>();
        boost::asio::async_read_until(*socket, *buffer, '\n',
            [this, socket, buffer](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    try {
                        std::istream is(buffer.get());
                        std::string line;
                        std::getline(is, line);
                        handle_message(socket, line);
                        handle_connection(socket);
                    }
                    catch (const std::exception& e) {
                        std::wcerr << L"Exception in handle_connection: " << e.what() << std::endl;
                    }
                }
                else {
                    std::wcerr << L"Error in async_read_until: " << string_to_wstring(ec.message()) << std::endl;
                }
            });
    }

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


    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    boost::asio::thread_pool pool_;
    std::wstring path_to_store = L"D:\\receive\\";
};

int main() {
    try {

        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);

        std::wcout << L"SERVER" << std::endl;

        boost::asio::io_context io_context;
        Server server(io_context, 8888);

        io_context.run();
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}