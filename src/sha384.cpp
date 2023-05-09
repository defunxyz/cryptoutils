// Copyright (C) Fisnik. All rights reserved.
// Performs Hashing using Secure Hash Algorithm 2, utilizing the SHA-384 cryptographic hash function.
#include <iostream>
#include "common.h"

void print_help() 
{
    std::string msg = R"(
        sha384 -- SHA384 Cryptographic String Hash Generator
        Usage:
            sha384  [-m plaintext]
            sha384  [-m plaintext] [-v hash]
        
        Command line options:
            -h --help	       Display the help.
            -m, --message      A plain text message.
            -v, --verify       A sha256 hash string to check against.
    )";

    std::cout << msg << "\n";
}

void hash(const std::string& msg, SHA384& hash, std::string& out)
{
    StringSource src(reinterpret_cast<byte const*>(msg.c_str()),
        msg.size(), true, new HashFilter(hash, new HexEncoder(new StringSink(out))));
}

int main(int argc, const char* argv[]) 
{
    SHA384 m_hash;
    std::string m_message, m_output;

    if (argc < 2) {
        std::cerr << "No arguments passed in\n";
        print_help();
        return -1;
    }

    if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_help();
        return -1;
    }
    else if (strcmp(argv[1], "-m") == 0 && strcmp(argv[3], "-v") == 0) {
        m_message = argv[2];
        std::string m_input_hash = argv[4];
        hash(m_message, m_hash, m_output);
        
        std::string output = R"(
            Message: {}
            Message hash: {}
            Input hash: {}
            
            Report: {}
        )";

        fmt::print(output,
            fmt::styled(m_message, fmt::emphasis::italic | fg(fmt::color::sea_green)),
            fmt::styled(m_output, fmt::emphasis::bold | fg(fmt::color::cyan)),
            fmt::styled(m_input_hash, fmt::emphasis::bold | fg(fmt::color::cyan)),
            fmt::styled((m_input_hash == m_output) ? "Success: Both hashes match!" : "Failure: These hashesh didn't match!", 
                fmt::emphasis::bold | ((m_input_hash == m_output) ? fg(fmt::color::dark_green) : fg(fmt::color::dark_red))));
    }
    else {
        m_message = (strcmp(argv[2], "") == 0) ? m_message : argv[2];
        hash(m_message, m_hash, m_output);
        
        std::string output = R"(
            String: {}
            Hash: {}
        )";

        fmt::print(output,
            fmt::styled(m_message, fmt::emphasis::italic | fg(fmt::color::alice_blue)),
            fmt::styled(m_output, fmt::emphasis::bold | fg(fmt::color::cyan)));
    }

    return 0; 
}