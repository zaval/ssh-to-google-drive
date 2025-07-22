#ifndef ARGPARSER_H
#define ARGPARSER_H
#include <filesystem>
#include <fstream>
#include <vector>

#include "nlohmann/json.hpp"

/**
 * @class ProgramOptions
 * @brief A class to handle and manage program configuration and command-line options.
 *
 * This class is responsible for parsing, storing, and providing access to command-line
 * options or configurations for the program. It allows users to define options, retrieve
 * their values, and handle default values and validation for parameters.
 *
 * The class is designed to help in organizing program options for ease of use and
 * better code maintainability.
 */
struct ProgramOptions {
    std::filesystem::path service_account_file;
    std::string client_id;
    std::string secret;
    std::string ssh_host;
    std::string ssh_user;
    std::string ssh_password;
    int ssh_port;
    std::string ssh_keyfile;
    std::string ssh_keyfile_password;
    bool show_help = false;
    std::string ssh_folder;
    std::string gdrive_folder;
    std::vector<std::string> ignore;
    int threads = 1;

    void save_config() const {
        nlohmann::json config;
        config["client_id"] = client_id;
        config["secret"] = secret;
        config["ssh_host"] = ssh_host;
        config["ssh_user"] = ssh_user;
        config["ssh_password"] = ssh_password;
        config["ssh_port"] = ssh_port;
        config["ssh_keyfile"] = ssh_keyfile;
        config["ssh_keyfile_password"] = ssh_keyfile_password;
        config["gdrive_folder"] = gdrive_folder;
        config["ssh_folder"] = ssh_folder;
        config["service_account_file"] = service_account_file;
        config["ignore"] = ignore;
        std::ofstream ofs("config.json");
        ofs << std::setw(4) << config << std::endl;
    }

    ProgramOptions() {
        ssh_port = 22;

        std::ifstream ifs("config.json");
        if (ifs.is_open()) {
            const auto config = nlohmann::json::parse(ifs);
            if (config.contains("client_id"))
                client_id = config["client_id"];
            if (config.contains("secret"))
                secret = config["secret"];
            if (config.contains("ssh_host"))
                ssh_host = config["ssh_host"];
            if (config.contains("ssh_user"))
                ssh_user = config["ssh_user"];
            if (config.contains("ssh_password"))
                ssh_password = config["ssh_password"];
            if (config.contains("ssh_port"))
                ssh_port = config["ssh_port"];
            if (config.contains("ssh_keyfile"))
                ssh_keyfile = config["ssh_keyfile"];
            if (config.contains("ssh_keyfile_password"))
                ssh_keyfile_password = config["ssh_keyfile_password"];
            if (config.contains("gdrive_folder"))
                gdrive_folder = config["gdrive_folder"];
            if (config.contains("ssh_folder"))
                ssh_folder = config["ssh_folder"];
            if (config.contains("service_account_file"))
                service_account_file = config["service_account_file"].get<std::string>();
            if (config.contains("ignore"))
                ignore = config["ignore"];
            if (config.contains("threads"))
                threads = config["threads"].get<int>();
        }

        char *env = getenv("CLIENT_ID");
        if (env != nullptr)
            client_id = std::string(env);
        env = getenv("SECRET");
        if (env != nullptr)
            secret = std::string(env);
        env = getenv("HOME");
        if (env != nullptr)
            ssh_keyfile = std::string(getenv("HOME")) + "/.ssh/id_rsa";
        env = getenv("GOOGLE_SERVICE_ACCOUNT");
        if (env != nullptr)
            service_account_file = std::string(getenv("GOOGLE_SERVICE_ACCOUNT"));
    }
};


/**
 * @class ArgParser
 * @brief A class for parsing and managing command-line arguments.
 *
 * This class provides functionality to define, parse, and retrieve the values of
 * command-line arguments. It simplifies the process of handling user-provided input
 * through the command line by supporting argument registration, value retrieval,
 * and default value management.
 *
 * ArgParser is designed to improve the organization and readability of programs
 * that require handling multiple command-line arguments.
 */
class ArgParser {
public:
    ArgParser(int argc, char** argv);
    ProgramOptions parse() const;
    void print_help();
private:
    std::vector<std::string> args;
};



#endif //ARGPARSER_H
