#include <iostream>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <filesystem>
#include <fstream>
#include <semaphore>
#include <sys/fcntl.h>

#include "argparser.h"
#include "gdriveapi.h"
#include "md5.h"
#include "sftpclient.h"

#include <spdlog/spdlog.h>

#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <thread>
#include <queue>

#include "spdlog/fmt/bundled/std.h"

namespace fs = std::filesystem;

constexpr size_t chunk_size = 512 * 1024;
bool has_interactive_console = true;


struct Task {
    std::string name;
    std::string ssh_folder;
    std::string gdrive_folder;
    uint64_t size;
};

std::queue<Task> tasks_queue;
std::mutex tasks_queue_mutex;
std::condition_variable tasks_queue_cv;
std::atomic<bool> is_running{true};
std::counting_semaphore semaphore(100);

void file_uploader(const ProgramOptions &options, GDriveAPI *gapi) {

    auto md5_file = spdlog::get("md5file_logger");

    const auto thread_id = std::this_thread::get_id();
    const auto tid = std::hash<std::thread::id>{}(thread_id) % options.threads + 1;

    while (is_running || !tasks_queue.empty()) {
        std::unique_lock<std::mutex> lock(tasks_queue_mutex);
        tasks_queue_cv.wait(lock, [] { return !tasks_queue.empty() || !is_running; });

        if (!tasks_queue.empty()) {
            Task task = tasks_queue.front();
            tasks_queue.pop();
            lock.unlock();

            const auto sftp = std::make_unique<SFTPClient>(options.ssh_host, options.ssh_port);
            auto res = false;
            if (options.ssh_password.empty()) {
                res = sftp->connect(options.ssh_user, options.ssh_keyfile, options.ssh_keyfile_password);
            } else {
                res = sftp->connect(options.ssh_user, options.ssh_password);
            }

            if (!res) {
                spdlog::error("[{}] Cannot connect to {}", tid, options.ssh_host);
                return;
            }


            // BEGIN WORKER


            spdlog::info("[{}] Processing file {}/{} size: {}", tid, task.ssh_folder, task.name, std::to_string(task.size));

            if (task.size == 0) {
                spdlog::info("[{}] Empty file {}/{}", tid, task.ssh_folder, task.name);
                gapi->create_file(task.name, "text/plain", task.gdrive_folder);
                continue;
            }

            const auto md5 = MD5();
            size_t offset = 0;
            long read_bytes = 0;

            const auto upload_url = gapi->create_file_for_upload(task.name, task.gdrive_folder);
            if (upload_url.empty()) {
                spdlog::error("[{}] Cannot create upload url for {}/{}", tid, task.ssh_folder, task.name);
                continue;
            }

            const auto file_path = task.ssh_folder + "/" + task.name;

            auto file = sftp->open_file(file_path,O_RDONLY);
            if (file == nullptr) {
                spdlog::error("[{}] Cannot open file {}", tid, file_path);
                return;
            }

            FileChunkResponse upload_chunk_response{};
            while (offset < task.size) {
                read_bytes = 0;
                auto buffer = std::make_unique<char[]>(chunk_size);
                sftp->read_file(read_bytes, file, buffer.get(), chunk_size);
                upload_chunk_response = gapi->upload_file_chunk(upload_url, buffer.get(), read_bytes, offset, task.size);
                offset += read_bytes;
                if (has_interactive_console) {
                    auto percent = offset * 100 / task.size;
                    std::cout << "\r\x1b[2K" << task.name << " " << percent << "% (" << offset << "/" << task.size << ")" << std::flush;
                }

                if (!md5.update(buffer.get(), read_bytes)) {
                    spdlog::error("[{}] Cannot update md5 for {}", tid, task.name);
                }
            }
            if (has_interactive_console)
                std::cout << std::endl;

            const auto md5_checksum = md5.hexdigest();
            if (upload_chunk_response.success && !upload_chunk_response.file_id.empty()) {
                const auto file_md5 = gapi->get_file_md5(upload_chunk_response.file_id);
                if (file_md5 == md5_checksum) {
                    spdlog::info("[{}] Checksum correct {}/{}", tid, task.ssh_folder, task.name);
                } else {
                    spdlog::error("[{}] MD5 mismatch for {}/{}: {} != {}", tid, task.ssh_folder, task.name, file_md5, md5_checksum);
                    sftp->close_file(file);
                    continue;

                }
            } else if (task.size == 0) {
                spdlog::info("[{}] Empty file {}/{}", tid, task.ssh_folder, task.name);
            } else {
                spdlog::error("[{}] Cannot upload file {}/{}", tid, task.ssh_folder,  task.name);
                sftp->close_file(file);
                // std::cerr << "Cannot upload file " << entry.name << std::endl;
                continue;
            }

            sftp->close_file(file);
            md5_file->info("{}\t{}", md5_checksum, file_path);

            // END WORKER


            semaphore.release();
        }
    }
}

nlohmann::json load_local_tree(const std::string &path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        spdlog::error("Cannot open file {}", path);
        return {};
    }
    nlohmann::json json = nlohmann::json::parse(file);
    return json;

}

void process_local_tree(const std::string &path, const nlohmann::json tree_json) {
    spdlog::info("{}", path);
    for (const auto& obj : tree_json) {
        // spdlog::info("Processing value {}",obj.dump(4));
        if (!obj.is_object()) {
            spdlog::error("Value is not an object");
            continue;
        }
        if (obj["type"].get<std::string>() == "file") {
            spdlog::info("{}/{}", path, obj["name"].get<std::string>());
        }
        if (obj["type"].get<std::string>() == "directory") {
            const auto new_path = path.empty() ? obj["name"].get<std::string>() : path + "/" + obj["name"].get<std::string>();
            if (obj.contains("contents")) {
                process_local_tree(new_path, obj["contents"]);
            }

        }

        // if (value.is_object()) {
        //     const auto new_path = path + "/" + key;
        //     process_local_tree(new_path, value);
        // } else if (value.is_string()) {
        //     const auto file_path = path + "/" + key;
        //     const auto file_size = fs::file_size(file_path);
        //     const auto md5 = MD5();
        //     std::ifstream file(file_path, std::ios::binary);
        //     if (!file.is_open()) {}
        // }
    }
}

void load_sftp_tree(SFTPClient *sftp, const std::string &path, std::vector<std::string> &files) {
    spdlog::info("Opening directory {}", path);
    const auto entries = sftp->ls(path);
    for (const auto &entry: entries) {
        if (entry.type == FILE_TYPE) {
            files.push_back(path + "/" + entry.name);
        } else {
            load_sftp_tree(sftp, path + "/" + entry.name, files);
            // files.insert(files.end(), load_sftp_tree(sftp, path + "/" + entry.name).begin(), load_sftp_tree(sftp, path + "/" + entry.name).end());
        }
    }
}


void process_sftp_directory(const ProgramOptions &options, const std::vector<std::string> &processed_files, const std::string &path, GDriveAPI* gapi, const std::string& gdrive_folder) {
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
        return;
    }
    const auto entries = sftp->ls(path);
    spdlog::info("Processing directory {}", path);

    std::vector<std::string> directories{};
    for (const auto &entry: entries) {
        if (entry.type == DIRECTORY_TYPE) {
            directories.push_back(path + "/" + entry.name);
        } else {
            semaphore.acquire();
            Task task{entry.name, path, gdrive_folder, entry.size};
            {
                std::lock_guard<std::mutex> lock(tasks_queue_mutex);
                tasks_queue.push(task);
            }
            tasks_queue_cv.notify_one();
            spdlog::info("Task added: {}/{}", path, entry.name);
        }
    }

    for (const auto& dirname : directories) {
        const auto new_gdrive_folder = gapi->create_folder(fs::path(dirname).filename(), gdrive_folder);
        process_sftp_directory(options, processed_files, dirname, gapi, new_gdrive_folder);
    }
}


int main(int argc, char **argv) {
    spdlog::flush_every(std::chrono::seconds(3));
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/log.txt", true);
    spdlog::logger logger("ssh_to_gdrive", {console_sink, file_sink});
    spdlog::set_default_logger(std::make_shared<spdlog::logger>(logger));

    auto md5_file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("md5files.txt", false);
    auto md5_file_logger = std::make_shared<spdlog::logger>("md5file_logger", md5_file_sink);
    md5_file_logger->set_level(spdlog::level::info);
    md5_file_logger->set_pattern("%v");
    spdlog::register_logger(md5_file_logger);

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



    const auto tree_json = load_local_tree("../tree.json");

    process_local_tree("", tree_json);

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


    std::vector<std::thread> upload_threads;
    for (int i = 0; i < options.threads; ++i) {
        upload_threads.emplace_back(file_uploader, options, gapi.get());
    }

    process_sftp_directory(options, processed_files, ".", gapi.get(), gdrive_folder);
    is_running = false;
    tasks_queue_cv.notify_all(); // Wake up all waiting threads
    spdlog::info("Finished processing files");

    for (auto& thread : upload_threads) {
        thread.join();
    }
    return 0;
}
