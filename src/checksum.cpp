// Copyright (C) Fisnik. All rights reserved.
#include <set>
#include "common.h"
#include "type_traits.h"
#include "crypto++/sha.h"

void print_help()
{
    std::string msg = R"(
        checksum -- Generate checksum of file or file(s)
        Usage:
            checksum  [-f path]
            checksum  [-d path] [*.*]
        
        Command line options:
            -h --help	     Display the help.
            -f, --file       A path to a file, or multiple files. 
    )";
}

struct checksum_info {
    std::string filename;
    std::set<std::string> hashes;
};

template<typename T>
void hash(const std::string& filename, T* algorithm, checksum_info& info)
{
    HashTransformation& ht = algorithm;
    std::string& out;
    FileSource(filename.c_str(), true, new HashFilter(ht, new HexEncoder(new StringSink(out))));
    info.hashes.insert(out);
}

void recursive_file_hash(const fs::path directory, std::string filter = "*.*")
{
    bool m_filter = false;

    if(filter != "*.*")
        m_filter = true;

    for(const auto& file : fs::recursive_directory_iterator(directory)) {
        std::string m_hash;
        std::string filename = file.path().filename().string();

        if(m_filter){
            std::string ext = file.path().filename().extension().string();
            if(strcmp(&ext[1], &filter[1]) != 0) {
                continue;
            } 
        }

        checksum_info m_info;
        m_info.filename = filename;
        hash<SHA1>(filename, new SHA1(), m_info);
        hash<SHA256>(filename, new SHA256(), m_info);
        hash<SHA384>(filename, new SHA384(), m_info);
    }
}

template<typename T>
typename std::enable_if<is_vector<T>::value>::type pretty_print(const T& x){
    for(auto f: x){}
}

template<typename T>
typename std::enable_if<!is_vector<T>::value>::type pretty_print(const T& x){}


int main(int argc, const char* argv[]) {
    
    std::string filename;
    std::vector<checksum_info> m_checksums;

    if (argc < 2) {
        std::cerr << "No arguments passed in\n";
        print_help();
        return -1;
    }

    if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_help();
        return -1;
    }
    else if (strcmp(argv[1], "-d") == 0 && strncmp(argv[3], "*.", 2) == 0) {
        recursive_file_hash(fs::path(argv[2]), argv[3]);
    }
    else {
        const fs::path m_path(argv[2]);
        if(fs::exists(m_path) && !fs::is_directory(m_path)){
            filename = m_path.filename().string();
            
            checksum_info m_info;
            m_info.filename = filename;
            
            hash<SHA1>(filename, new SHA1(), m_info);
            hash<SHA256>(filename, new SHA256(), m_info);
            hash<SHA384>(filename, new SHA384(), m_info);
            pretty_print<checksum_info>(m_info);
        }
    }

    return 0;
}