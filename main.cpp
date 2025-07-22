#include <iostream>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <filesystem>
#include <fstream>
#include <sys/fcntl.h>

#include "argparser.h"
#include "gdriveapi.h"
#include "md5.h"
#include "sftpclient.h"

#include <spdlog/spdlog.h>

#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

namespace fs = std::filesystem;

constexpr size_t chunk_size = 512 * 1024;
bool has_interactive_console = true;


void process_sftp_directory(SFTPClient *sftp, const std::string &path, GDriveAPI* gapi, const std::string& gdrive_folder) {
    const auto entries = sftp->ls(path);
    spdlog::info("Processing directory {}", path);

    std::vector<std::string> directories{};
    for (const auto &entry: entries) {
        if (entry.type == DIRECTORY_TYPE) {
            directories.push_back(path + "/" + entry.name);
        } else {

            const auto size = entry.size;
            spdlog::info("Processing file {}/{} size: {}", path, entry.name, std::to_string(size));

            if (size == 0) {
                spdlog::info("Empty file {}/{}", path, entry.name);
                gapi->create_file(entry.name, "text/plain", gdrive_folder);
                continue;
            }

            const auto md5 = MD5();
            size_t offset = 0;
            long read_bytes = 0;

            const auto upload_url = gapi->create_file_for_upload(entry.name, gdrive_folder);
            if (upload_url.empty()) {
                spdlog::error("Cannot create upload url for {}/{}", path, entry.name);
                // std::cerr << "Error creating upload url" << std::endl;
                continue;
            }

            const auto file_path = path + "/" + entry.name;

            auto file = sftp->open_file(file_path,O_RDONLY);
            if (file == nullptr) {
                spdlog::error("Cannot open file {}", file_path);
                return;
            }
            FileChunkResponse upload_chunk_response{};
            while (offset < size) {
                read_bytes = 0;
                auto buffer = new char[chunk_size];
                sftp->read_file(read_bytes, file, buffer, chunk_size);
                upload_chunk_response = gapi->upload_file_chunk(upload_url, buffer, read_bytes, offset, size);
                offset += read_bytes;
                if (has_interactive_console) {
                    auto percent = offset * 100 / size;
                    std::cout << "\r\x1b[2K" << entry.name << " " << percent << "% (" << offset << "/" << size << ")" << std::flush;
                }

                if (!md5.update(buffer, read_bytes)) {
                    spdlog::error("Cannot update md5 for {}", entry.name);
                    // std::cerr << "cannot update md5" << std::endl;
                }
                delete[] buffer;
            }
            if (has_interactive_console)
                std::cout << std::endl;

            const auto md5_checksum = md5.hexdigest();
            if (upload_chunk_response.success && !upload_chunk_response.file_id.empty()) {
                const auto file_md5 = gapi->get_file_md5(upload_chunk_response.file_id);
                if (file_md5 == md5_checksum) {
                    spdlog::info("Checksum correct {}/{}", path, entry.name);
                } else {
                    spdlog::error("MD5 mismatch for {}/{}: {} != {}", path, entry.name, file_md5, md5_checksum);
                    sftp->close_file(file);
                    continue;

                }
            } else if (size == 0) {
                spdlog::info("Empty file {}/{}", path, entry.name);
            } else {
                spdlog::error("Cannot upload file {}/{}", path,  entry.name);
                sftp->close_file(file);
                // std::cerr << "Cannot upload file " << entry.name << std::endl;
                continue;
            }
            sftp->close_file(file);
            std::ofstream ofs("md5files.txt", std::ios::app);
            ofs << md5_checksum << "\t" << path << "/" << entry.name << std::endl;
        }
    }

    for (const auto& dirname : directories) {
        const auto new_gdrive_folder = gapi->create_folder(fs::path(dirname).filename(), gdrive_folder);
        process_sftp_directory(sftp, dirname, gapi, new_gdrive_folder);
    }
}


int main(int argc, char **argv) {
    spdlog::flush_every(std::chrono::seconds(3));
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/log.txt", true);
    spdlog::logger logger("ssh_to_gdrive", {console_sink, file_sink});
    spdlog::set_default_logger(std::make_shared<spdlog::logger>(logger));

    std::string line;
    std::vector<std::string> processed_files;
    std::map<std::string, std::string> known_md5;
    std::ifstream md5_file("md5files.txt");
    while (std::getline(md5_file, line)) {
        size_t tab_pos = line.find('\t');
        if (tab_pos != std::string::npos) {
            const auto path = line.substr(tab_pos + 1);
            processed_files.push_back(path);
        }
    }


    const auto debian_frontend = getenv("DEBIAN_FRONTEND");
    if (debian_frontend != nullptr && strcmp(debian_frontend, "noninteractive") == 0) {
        has_interactive_console = false;
    }

    ArgParser parser(argc, argv);
    ProgramOptions options;
    try {
        options = parser.parse();
    } catch (std::runtime_error const& e) {
        spdlog::error("{}", e.what());
        // std::cerr << e.what() << std::endl;
        return 1;
    }

    if (options.show_help) {
        parser.print_help();
        return 0;
    }

    // options.save_config();
    // return 0;

    const auto sftp = std::make_unique<SFTPClient>(options.ssh_host, options.ssh_port);
    sftp->set_ignore_files(options.ignore);
    sftp->set_processed_files(processed_files);
    auto res = false;
    if (options.ssh_password.empty()) {
        res = sftp->connect(options.ssh_user, options.ssh_keyfile, options.ssh_keyfile_password);
    } else {
        res = sftp->connect(options.ssh_user, options.ssh_password);
    }

    if (!res) {
        spdlog::error("Cannot connect to {}", options.ssh_host);
        // std::cerr << "Cannot connect to " << options.ssh_host << std::endl;
        return -1;
    }

    std::unique_ptr<GDriveAPI> gapi;

    auto gdrive_folder = options.gdrive_folder;

    if (!options.service_account_file.empty()) {
        // gapi = new GDriveAPI(options.service_account_file);
        gapi = std::make_unique<GDriveAPI>(options.service_account_file);
        gapi->authorize_from_service_account();
    } else {
        // gapi = new GDriveAPI(options.client_id, options.secret);
        gapi = std::make_unique<GDriveAPI>(options.client_id, options.secret);
        gapi->authorize();
        if (const auto file_info = gapi->get_file_info(gdrive_folder); file_info.empty()) {
            gdrive_folder = gapi->create_folder(gdrive_folder);
        }
    }

    process_sftp_directory(sftp.get(), ".", gapi.get(), gdrive_folder);

    return 0;
}
