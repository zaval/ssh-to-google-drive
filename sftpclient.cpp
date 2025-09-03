#include "sftpclient.h"

#include <iostream>
#include <cstring>
#include <regex>

#include "spdlog/spdlog.h"

SFTPClient::SFTPClient(const std::string &hostname, const int &port):
    hostname(hostname),
    port(port)
{
    session = ssh_new();
    if (session == nullptr) {
        throw std::runtime_error("Error creating ssh session");
    }
    int verbosity = SSH_LOG_PROTOCOL;
    ssh_options_set(session, SSH_OPTIONS_HOST, hostname.c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    // ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
}

SFTPClient::~SFTPClient() {
    sftp_free(sftp);
    ssh_disconnect(session);
    ssh_free(session);
}

bool SFTPClient::connect(const std::string &username, const std::string &password) {
    ssh_options_set(session, SSH_OPTIONS_USER, username.c_str());
    if (!connect_to_host()) {
        return false;
    }
    auto rc = ssh_userauth_password(session, username.c_str(), password.c_str());
    if (rc != SSH_AUTH_SUCCESS)
    {
        spdlog::error("Error authenticating with password: {}", ssh_get_error(session));
        // std::cerr << "Error authenticating with key file: " << ssh_get_error(session) << std::endl;
        ssh_disconnect(session);
        ssh_free(session);
        return false;
    }
    return init_sftp();
}

bool SFTPClient::connect(const std::string &username, const fs::path &key_file, const std::string &password) {

    ssh_options_set(session, SSH_OPTIONS_USER, username.c_str());
    if (!connect_to_host()) {
        return false;
    }

    const char *passphrase = nullptr;
    if (!password.empty()) {
        passphrase = password.c_str();
    }
    auto rc = ssh_userauth_privatekey_file(session, username.c_str(), key_file.c_str(), passphrase);
    if (rc != SSH_AUTH_SUCCESS)
    {
        spdlog::error("Error authenticating with key file: {}", ssh_get_error(session));
        // std::cerr << "Error authenticating with key file: " << ssh_get_error(session) << std::endl;
        ssh_disconnect(session);
        ssh_free(session);
        return false;
    }

    return init_sftp();
}

std::vector<SFTPEntry> SFTPClient::ls(const std::string &path) {
    std::vector<SFTPEntry> entries{};

    auto dir = sftp_opendir(sftp, path.c_str());
    if (!dir)
    {
        spdlog::error("Error opening directory: {}", ssh_get_error(session));
        // std::cerr << "Error opening directory: " << ssh_get_error(session) << std::endl;
        return {};
    }
    sftp_attributes attributes;
    while ((attributes = sftp_readdir(sftp, dir)) != nullptr) {
        if (strcmp(attributes->name, ".") == 0 || strcmp(attributes->name, "..") == 0) {
            sftp_attributes_free(attributes);
            continue;
        }

        if (std::ranges::find(processed_files, std::string(path + "/" + attributes->name)) != processed_files.end()) {
            spdlog::info("File {}/{} was already processed", path, attributes->name);
            sftp_attributes_free(attributes);
            continue;
        }

        // if (std::ranges::find(ignore_files, attributes->name) != ignore_files.end()) {
        if (std::ranges::find_if(ignore_files, [&attributes](const std::string &val) {
            const std::regex self_regex(val, std::regex_constants::ECMAScript | std::regex_constants::icase);
            return std::regex_search(attributes->name, self_regex);
        }) != ignore_files.end()) {
            spdlog::info("Ignore file: {}", attributes->name);
            // std::cout << "Ignore file: " << attributes->name << std::endl;
            sftp_attributes_free(attributes);
            continue;
        }
        auto type = SFTP_FILE_TYPE::FILE_TYPE;
        if (attributes->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            type = SFTP_FILE_TYPE::DIRECTORY_TYPE;
        }
        entries.push_back(
            {attributes->name,
                type,
                attributes->size,
                attributes->uid,
                attributes->gid,
                attributes->permissions,
                attributes->atime64,
                attributes->createtime,
                attributes->mtime64
            }
        );
    }
    sftp_attributes_free(attributes);
    sftp_closedir(dir);

    return entries;
}

sftp_file SFTPClient::open_file(const std::string &path, const int &mode) {
    auto file = sftp_open(sftp, path.c_str(),
                         mode, 0);
    if (file == nullptr) {
        spdlog::error("Error opening file: {}", ssh_get_error(session));
        // std::cerr << "Error opening file: " << ssh_get_error(session) << std::endl;
        return nullptr;
    }
    return file;
}

bool SFTPClient::close_file(sftp_file file) const {
    return sftp_close(file) == SSH_OK;
}

void SFTPClient::read_file(long &read_bytes, const sftp_file &file, char *buffer, const size_t &chunk_size) const {
    while (read_bytes < chunk_size) {
        const auto tmp_read_bytes = sftp_read(file, &buffer[read_bytes], chunk_size-read_bytes);
        if (tmp_read_bytes == 0) {
            return;; // EOF
        } else if (tmp_read_bytes < 0) {
            spdlog::error("Error reading file: {}", ssh_get_error(session));
            // std::cerr << "Error reading file: " << ssh_get_error(session) << std::endl;
            return;
        }
        read_bytes += tmp_read_bytes;
    }
}

void SFTPClient::set_ignore_files(const std::vector<std::string> &ignore_files) {
    this->ignore_files = ignore_files;
}

void SFTPClient::set_processed_files(const std::vector<std::string> &files) {
    this->processed_files = files;
}

bool SFTPClient::connect_to_host() const {

    ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes");
    // const auto verbocity = SSH_LOG_FUNCTIONS;
    // ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbocity);

    auto rc = ssh_connect(session);
    if (rc != SSH_OK)
    {
        spdlog::error("Error connecting to {}: {}", hostname, ssh_get_error(session));
        // std::cerr << "Error connecting to " << hostname << ": " << ssh_get_error(session) << std::endl;
        return false;
    }
    return true;
}

bool SFTPClient::init_sftp() {
    sftp = sftp_new(session);
    if (sftp == nullptr)
    {
        spdlog::error("Error allocating SFTP session: {}", ssh_get_error(session));
        // std::cerr << "Error allocating SFTP session: " << ssh_get_error(session) << std::endl;
        return false;
    }
    auto rc = sftp_init(sftp);
    if (rc != SSH_OK)
    {
        spdlog::error("Error initializing SFTP session: {}", ssh_get_error(session));
        // std::cerr << "Error initializing SFTP session: " << ssh_get_error(session) << std::endl;
        sftp_free(sftp);
        return false;
    }
    return true;
}
