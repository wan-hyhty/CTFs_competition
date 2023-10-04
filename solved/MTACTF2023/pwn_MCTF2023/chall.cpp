
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <thread>
#include <boost/asio.hpp>
#include <sys/wait.h>

using namespace boost::asio;
using ip::tcp;

const std::regex validCommandRegex("^fping -c1 -t200 (?:(?:25[0-5]|2[0-4]\\d|1?\\d{1,2})(?:\\.(?!$)|$)){4}$");
char data[300];
std::string hello_str = "send IPv4 address to execute ping and more ...\n";

void handleClient(tcp::socket socket) {
    try {
        boost::system::error_code ec;
        write(socket, buffer(hello_str), ec);
        size_t length = socket.read_some(buffer(data+16, 300-17));
        size_t count = 0;
        data[0] = 'f';
        data[1] = 'p';
        data[2] = 'i';
        data[3] = 'n';
        data[4] = 'g';
        data[5] = ' ';
        data[6] = '-';
        data[7] = 'c';
        data[8] = '1';
        data[9] = ' ';
        data[10] = '-';
        data[11] = 't';
        data[12] = '2';
        data[13] = '0';
        data[14] = '0';
        data[15] = ' ';
        data[length+15] = NULL;
        std::string receivedString(data, length+15);
        if (std::regex_match(receivedString, validCommandRegex)) {
            for(int i=0; i < 2; i ++){
                int x= 0;
                pid_t pid = fork();
                if (pid == -1) {
                    std::cerr << "Fork failed." << std::endl;
                    return;
                } else if (pid == 0) {
                    x = execl("/bin/sh", "sh", "-c", data, (char *) NULL);
                    return;
                } else {
                    int status;
                    waitpid(pid, &status, 0);

                    if (WIFEXITED(status)) {
                        int exitCode = WEXITSTATUS(status);
                        std::cout << "Child process exited with code: " << exitCode << std::endl;
                    }
                }
                if(x != -1){
                    count += 1;
                }
            }
        }
        if(count > 3){
            std::ifstream inputFile("/flag"); // Open the file
            if (!inputFile.is_open()) {
                std::cerr << "Error opening file." << std::endl;
                return;
            }
            std::string line;
            while (std::getline(inputFile, line)) {
                std::cout << line << std::endl;
            }
            inputFile.close(); // Close the file 
        }
        std::string end_str="Done!!\n";
        write(socket, buffer(end_str), ec);
        socket.close();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}

int main() {
    io_context ioContext;

    tcp::acceptor acceptor(ioContext, tcp::endpoint(tcp::v4(), 1337));

    while (true) {
        tcp::socket socket(ioContext);
        acceptor.accept(socket);

        std::thread(handleClient, std::move(socket)).detach();
    }
    return 0;
}
